---
arquivo_original: "test_orca_integration.py"
caminho_deal: "Orca"
mime_type: "text/x-python-script"
data_conversao: "2026-10-20T23:01:28.859Z"
---

#!/usr/bin/env python3
"""A worked example of the ORCA NAV reporting API, in Python, against phi.

The same five steps as nav-report-sample.sh — get a token, list the groups, pull
a window of snapshots, pull the positions behind them, then page through the
whole window the way a scheduled puller would. This one is the reference for an
integrator writing in Python rather than shell, so it also shows the two things
that bite Python callers specifically: decimals and the private CA.

Meant to be READ as much as run. Every step prints the request it made.

    ./scripts/nav-report-sample.py
    ./scripts/nav-report-sample.py --group B1
    ./scripts/nav-report-sample.py --from 2026-08-01T00:00:00Z --to 2026-08-24T00:00:00Z
    ./scripts/nav-report-sample.py --env-file /path/to/other.env

Configuration comes from an env file (scripts/phi.env by default) and from the
process environment, which wins over the file so a scheduler can inject secrets
without writing them to disk. The client secret is never taken as an argument:
an argument is visible in `ps` and lands in shell history.

    ORCA_CORE_URL                 https://core.orca.phi.sys.srv.br
    AUTHENTIK_HOST                https://auth.orca.phi.sys.srv.br
    ORCA_REPORTING_CLIENT_ID      orca-reporting
    ORCA_REPORTING_CLIENT_SECRET  required
    ORCA_CA_BUNDLE                PEM holding the CA that signed phi's ingress

Standard library only, deliberately: an integrator should be able to run this
before deciding what to add to their dependency list.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = HERE / "phi.env"
TIMEOUT = 30


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
# Colour only when stdout is a terminal, so piping this into a file or a log
# does not fill it with escape sequences.
_TTY = sys.stdout.isatty()


def bold(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m" if _TTY else f"\n{text}")


def dim(text: str) -> None:
    print(f"\033[2m{text}\033[0m" if _TTY else text)


def die(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def load_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE file.

    Deliberately not a dotenv library: no interpolation, no `export`, no shell
    quoting rules. A secret that changes meaning depending on whether something
    unquoted it is a bad secret, and the failure — a client_secret silently
    missing its last character — presents as `invalid_client`, which names the
    client rather than the parsing.
    """
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die(f"{path}:{lineno}: expected KEY=VALUE, got: {raw!r}")
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def config(env_file: Path) -> dict[str, str]:
    from_file = load_env_file(env_file)

    def get(key: str, default: str | None = None) -> str | None:
        # Process environment wins. The file is the convenience; an operator or
        # a scheduler overriding one value should not have to edit it.
        #
        # Presence, not truthiness. `FOO=` in the environment means "explicitly
        # empty" and must beat the file — otherwise ORCA_CA_BUNDLE= cannot fall
        # back to the system trust store without editing phi.env, which is the
        # one thing the environment override exists to avoid.
        if key in os.environ:
            return os.environ[key]
        if key in from_file:
            return from_file[key]
        return default

    core = get("ORCA_CORE_URL")
    auth = get("AUTHENTIK_HOST")
    secret = get("ORCA_REPORTING_CLIENT_SECRET")

    missing = [
        name
        for name, value in (
            ("ORCA_CORE_URL", core),
            ("AUTHENTIK_HOST", auth),
            ("ORCA_REPORTING_CLIENT_SECRET", secret),
        )
        if not value
    ]
    if missing:
        die(
            f"missing {', '.join(missing)}\n"
            f"  looked in the environment and in {env_file}\n"
            f"  copy {DEFAULT_ENV_FILE.name}.example and fill it in"
        )

    return {
        "core": core.rstrip("/"),
        "auth": auth.rstrip("/"),
        "client_id": get("ORCA_REPORTING_CLIENT_ID", "orca-reporting"),
        "client_secret": secret,
        "ca_bundle": get("ORCA_CA_BUNDLE", ""),
    }


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
def tls_context(ca_bundle: str) -> ssl.SSLContext | None:
    """Trust phi's private CA. Verification stays ON.

    phi's ingress is signed by an internal CA, so the public trust store does
    not contain it. The answer is to pin that CA, never to stop verifying — a
    client that skips verification will happily talk to anything that answers on
    the hostname, which is the whole attack this protects against.

    There is one subtlety, and it is why this function exists rather than a
    plain `cafile=` argument. Python 3.13 turned on VERIFY_X509_STRICT by
    default, and the Vitra CA certificate carries

        X509v3 Basic Constraints:      <-- present, but NOT marked critical
            CA:TRUE

    RFC 5280 says a CA's basicConstraints MUST be critical. curl and the Go
    clients accept it anyway; strict OpenSSL does not, and Python 3.13 fails
    with `Basic Constraints of CA cert not marked critical` where every other
    tool on the machine succeeds. Clearing that one flag is a narrow, named
    relaxation: chain building, expiry, signatures and hostname matching are all
    still enforced — `check_hostname` and CERT_REQUIRED are untouched.

    The real fix is upstream: reissue the CA with basicConstraints marked
    critical. Until then every Python 3.13+ consumer of this API hits this, so it
    is documented here rather than rediscovered.
    """
    if not ca_bundle:
        # Nothing pinned: the system trust store applies, which is correct for a
        # publicly-signed host and will simply fail on phi.
        return None

    path = Path(ca_bundle).expanduser()
    if not path.is_absolute():
        path = (HERE / path).resolve()
    if not path.is_file():
        die(f"ORCA_CA_BUNDLE does not exist: {path}")

    ctx = ssl.create_default_context(cafile=str(path))
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    return ctx


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def request(
    url: str,
    ctx: ssl.SSLContext | None,
    *,
    data: bytes | None = None,
    token: str | None = None,
) -> dict:
    """One call. On failure, show the RFC 9457 problem document.

    urllib raises on 4xx/5xx, and the exception IS the response — so the body,
    which is where the API explains itself, is readable. Letting the exception
    propagate would print a stack trace ending in `HTTP Error 403: Forbidden`
    and throw away the part that says which scope was missing.
    """
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        print(f"  HTTP {exc.code} {exc.reason}", file=sys.stderr)
        try:
            print(
                json.dumps(json.loads(body), indent=2), file=sys.stderr
            )  # problem+json
        except json.JSONDecodeError:
            print(body, file=sys.stderr)
        raise SystemExit(1) from None
    except urllib.error.URLError as exc:
        die(f"  cannot reach {url}: {exc.reason}")


def get(base: str, path: str, params: dict, ctx, token: str) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base}{path}?{query}" if query else f"{base}{path}"
    return request(url, ctx, token=token)


def claims_of(jwt: str) -> dict:
    """Read the payload without verifying it.

    Fine for printing diagnostics, and fine ONLY for that. This token was minted
    by a server we just authenticated to over pinned TLS; a token arriving from
    anywhere else must be verified against the issuer's JWKS before a single
    claim in it is believed.
    """
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # base64url, padding stripped
    return json.loads(base64.urlsafe_b64decode(payload))


# ---------------------------------------------------------------------------
def main() -> int:
    default_from = (datetime.now(timezone.utc) - timedelta(days=7)).replace(
        minute=0, second=0, microsecond=0
    )

    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # The docstring minus its first line, which is already the description.
        epilog="\n".join(__doc__.splitlines()[1:]).strip(),
    )
    parser.add_argument(
        "--group", metavar="CODE", help="customer group code; default is the first one"
    )
    parser.add_argument(
        "--from",
        dest="from_",
        metavar="ISO8601",
        default=default_from.strftime("%Y-%m-%dT%H:00:00Z"),
        help="window start, ISO 8601 (default: 7 days ago)",
    )
    parser.add_argument(
        "--to", metavar="ISO8601", help="window end, ISO 8601 (default: now, server side)"
    )
    parser.add_argument(
        "--page-size", type=int, default=25, help="rows per page in step 5"
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help=f"KEY=VALUE config (default: {DEFAULT_ENV_FILE})",
    )
    args = parser.parse_args()

    cfg = config(args.env_file)
    ctx = tls_context(cfg["ca_bundle"])
    api = f"{cfg['core']}/api/v1"

    dim(f"config   {args.env_file}")
    dim(f"core     {cfg['core']}")
    dim(f"authentik {cfg['auth']}")
    dim(f"CA       {cfg['ca_bundle'] or '(system trust store)'}")

    # -----------------------------------------------------------------------
    # 1. A token
    # -----------------------------------------------------------------------
    # client_credentials against the orca-reporting client. The `orca` scope is
    # REQUIRED: it carries the orca_groups claim Core authorizes against, and
    # without it the token is perfectly valid and every call answers 403.
    bold("1. Token")
    dim(f"POST {cfg['auth']}/application/o/token/  (client_credentials, scope=openid orca)")

    token_response = request(
        f"{cfg['auth']}/application/o/token/",
        ctx,
        data=urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "scope": "openid orca",
            }
        ).encode(),
    )

    token = token_response.get("access_token")
    if not token:
        die(f"no access_token in: {json.dumps(token_response, indent=2)}")

    claims = claims_of(token)
    print(f"  expires_in  {token_response.get('expires_in')} seconds")
    print(f"  issuer      {claims.get('iss')}")
    print(f"  audience    {claims.get('aud')}")
    groups = claims.get("orca_groups")
    print(f"  orca_groups {groups if groups else 'MISSING — did you ask for the orca scope?'}")

    # -----------------------------------------------------------------------
    # 2. What can be filtered by
    # -----------------------------------------------------------------------
    bold("2. Groups")
    dim(f"GET {api}/customer-groups")

    group_list = get(api, "/customer-groups", {}, ctx, token)
    for g in group_list:
        print(f"  {g['code']}  {g['customer_count']} customer(s)  — {g['name']}")

    group = args.group
    if not group:
        if not group_list:
            die("no groups defined; pass --group or create one")
        group = group_list[0]["code"]
        dim(f"  (no --group given, using {group})")

    window = {"from": args.from_, "to": args.to}

    # -----------------------------------------------------------------------
    # 3. The series
    # -----------------------------------------------------------------------
    bold(f"3. Snapshots — group={group}, from={args.from_}" + (f", to={args.to}" if args.to else ""))
    dim(f"GET {api}/nav/snapshots?group={group}&…&limit=5")

    snaps = get(api, "/nav/snapshots", {"group": group, **window, "limit": 5}, ctx, token)

    # The window is echoed back. Worth reading every time: omit `from` and you
    # get 24 hours, and a partial answer looks exactly like a complete one.
    print(f"  window   {snaps['from']} .. {snaps['to']}")
    print(
        f"  returned {snaps['count']} row(s) on this page, "
        f"more: {'yes' if snaps.get('next_cursor') else 'no'}\n"
    )

    header = f"  {'HOUR':<18}{'CUSTOMER':<13}{'VENUE':<16}{'EQUITY USD':>13}{'EQUITY BRL':>13}  STATUS"
    print(header)
    for row in snaps["snapshots"]:
        # Decimal, not float. Rounding here is for READING only — the wire value
        # is a full-precision string and that is what you store.
        usd = Decimal(row["equity_usd"])
        brl = Decimal(row["equity_brl"]) if row["equity_brl"] is not None else None
        print(
            f"  {row['as_of_hour'][:16].replace('T', ' '):<18}"
            f"{row['customer_code']:<13}"
            f"{row['venue_code']:<16}"
            f"{usd:>13.2f}"
            f"{(f'{brl:.2f}' if brl is not None else 'no rate'):>13}"
            f"  {row['status']}"
        )

    # Zero rows is a 200, not a 404, and that is deliberate: "no such group" and
    # "no snapshots in that window" are both legitimately empty, and the server
    # cannot tell a typo from a quiet week. Which means a wrong --group looks
    # exactly like a healthy empty result — check it yourself.
    if snaps["count"] == 0:
        dim("")
        dim(f"  No rows. Either nothing was snapshotted in this window, or '{group}' is")
        dim("  not a group — the server cannot tell those apart, so neither can this.")
        return 0

    # -----------------------------------------------------------------------
    # 4. The positions behind one of them
    # -----------------------------------------------------------------------
    # Same filters, same paging — the only difference is that each row carries
    # the holdings it was valued from.
    #
    # These are the positions AS AT that hour, not current ones. They were
    # written into the snapshot at capture time, which is the only reason an old
    # hour can be explained at all: marks are not retained, so nothing is
    # recomputable after the fact.
    bold("4. Positions — the same rows, with their holdings")
    dim(f"GET {api}/nav/snapshots/detail?group={group}&…&limit=1")

    detail = get(
        api, "/nav/snapshots/detail", {"group": group, **window, "limit": 1}, ctx, token
    )
    row = detail["snapshots"][0]
    for line in json.dumps(row, indent=2).splitlines():
        print(f"  {line}")

    # The reason every decimal on the wire is a JSON STRING, shown rather than
    # asserted. json.loads maps a JSON number to float, and float is binary: it
    # cannot hold these values, and the error is silent and cumulative.
    bold("   Why the decimals are strings")
    for position in row["positions"]:
        exact = Decimal(position["quantity"])
        through_float = Decimal(repr(float(position["quantity"])))
        marker = "  <-- lost digits" if exact != through_float else "  (survived)"
        print(f"  {position['asset']:<6} as string  {exact}")
        print(f"  {'':<6} via float  {through_float}{marker}")

    # -----------------------------------------------------------------------
    # 5. Paging the whole window
    # -----------------------------------------------------------------------
    # What a scheduled pull actually does. Keyset, not offset: hold
    # `next_cursor`, pass it back unmodified, stop when it comes back null. A
    # snapshot written while this loop runs cannot shift a later page and make it
    # skip a row.
    bold("5. Full pull — following next_cursor to the end")
    dim(f"GET .../nav/snapshots?group={group}&…&limit={args.page_size}  then &cursor=…")

    cursor: str | None = None
    pages = rows = partial = no_brl = 0
    total_usd = Decimal(0)

    while True:
        page = get(
            api,
            "/nav/snapshots",
            {"group": group, **window, "limit": args.page_size, "cursor": cursor},
            ctx,
            token,
        )
        pages += 1
        rows += page["count"]
        for r in page["snapshots"]:
            if r["status"] == "PARTIAL":
                partial += 1
            if r["equity_brl"] is None:
                no_brl += 1
            total_usd += Decimal(r["equity_usd"])

        print(f"  page {pages:<3} {page['count']:>3} row(s)")

        cursor = page.get("next_cursor")
        if not cursor:
            break

    print(f"\n  {rows} row(s) over {pages} page(s)")
    print(f"  sum of equity_usd: {total_usd}")

    # The two things a consumer has to handle rather than ignore.
    if partial:
        print(f"  {partial} row(s) are PARTIAL — the figure is a LOWER BOUND and `unpriced`")
        print("    names the assets that had no rate. Exclude them from averages.")
    else:
        print("  0 PARTIAL rows — every asset held had a rate in this window.")
    if no_brl:
        print(f"  {no_brl} row(s) have equity_brl = null — no USD/BRL rate resolved. Null,")
        print("    never zero: the account was not worth nothing.")

    # A gap in the hours is real. Snapshots cannot be backfilled — marks are not
    # retained — so the series has holes wherever Core was down. Do not
    # interpolate across one.
    bold("Done.")
    dim("Gaps in the hours are real data, not missing rows: a missed snapshot can")
    dim("never be backfilled, because the marks it would need were not kept.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())