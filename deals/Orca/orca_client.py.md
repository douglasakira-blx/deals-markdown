---
arquivo_original: "orca_client.py"
caminho_deal: "Orca"
mime_type: "text/x-python-script"
data_conversao: "2026-10-20T23:02:53.333Z"
---

"""
Cliente da API ORCA NAV reporting (phi).

O que este modulo faz:
  - Le phi.env (mesmo contrato que test_orca_integration.py).
  - Pede um token client_credentials (scope openid orca).
  - Lista customer groups, pagina snapshots e le /performance.

Variaveis (phi.env ou ambiente; ambiente ganha):
  ORCA_CORE_URL, AUTHENTIK_HOST, ORCA_REPORTING_CLIENT_SECRET  (obrigatorias)
  ORCA_REPORTING_CLIENT_ID  default orca-reporting
  ORCA_CA_BUNDLE            PEM da CA que assinou o ingress do phi

Regras fixas:
  - Nao imprime o client_secret.
  - TLS com CA pinada; VERIFY_X509_STRICT desligado (certificado Vitra).
  - Paging por next_cursor, nunca offset.
  - Valores monetarios na API sao strings; quem soma usa Decimal.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = HERE / "phi.env"
TIMEOUT = 30
PAGE_SIZE = 100
TOKEN_SKEW_SEC = 30


class OrcaError(Exception):
    """Falha de config, TLS ou HTTP. Mensagem ja e segura para a UI."""


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise OrcaError(f"{path}:{lineno}: expected KEY=VALUE, got: {raw!r}")
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def load_config(env_file: Path | None = None) -> dict[str, str]:
    path = env_file or DEFAULT_ENV_FILE
    from_file = load_env_file(path)

    def get(key: str, default: str | None = None) -> str | None:
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
        raise OrcaError(
            f"missing {', '.join(missing)}\n"
            f"  looked in the environment and in {path}\n"
            f"  copy {DEFAULT_ENV_FILE.name}.example and fill it in"
        )
    return {
        "core": core.rstrip("/"),
        "auth": auth.rstrip("/"),
        "client_id": get("ORCA_REPORTING_CLIENT_ID", "orca-reporting") or "orca-reporting",
        "client_secret": secret,
        "ca_bundle": get("ORCA_CA_BUNDLE", "") or "",
        "env_file": str(path),
    }


def tls_context(ca_bundle: str) -> ssl.SSLContext | None:
    if not ca_bundle:
        return None
    path = Path(ca_bundle).expanduser()
    if not path.is_absolute():
        path = (HERE / path).resolve()
    if not path.is_file():
        raise OrcaError(f"ORCA_CA_BUNDLE does not exist: {path}")
    ctx = ssl.create_default_context(cafile=str(path))
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def _request(
    url: str,
    ctx: ssl.SSLContext | None,
    *,
    data: bytes | None = None,
    token: str | None = None,
) -> dict:
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
        try:
            detail = json.dumps(json.loads(body), indent=2)
        except json.JSONDecodeError:
            detail = body
        raise OrcaError(f"HTTP {exc.code} {exc.reason}\n{detail}") from None
    except urllib.error.URLError as exc:
        raise OrcaError(f"cannot reach {url}: {exc.reason}") from None


class OrcaClient:
    def __init__(self, env_file: Path | None = None) -> None:
        self.cfg = load_config(env_file)
        self.ctx = tls_context(self.cfg["ca_bundle"])
        self.api = f"{self.cfg['core']}/api/v1"
        self._token: str | None = None
        self._token_expires_at = 0.0

    def token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expires_at - TOKEN_SKEW_SEC:
            return self._token
        payload = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.cfg["client_id"],
                "client_secret": self.cfg["client_secret"],
                "scope": "openid orca",
            }
        ).encode()
        resp = _request(
            f"{self.cfg['auth']}/application/o/token/",
            self.ctx,
            data=payload,
        )
        token = resp.get("access_token")
        if not token:
            raise OrcaError("no access_token in token response")
        self._token = token
        self._token_expires_at = now + int(resp.get("expires_in") or 600)
        return token

    def get(self, path: str, params: dict) -> dict | list:
        query = urllib.parse.urlencode(
            {k: v for k, v in params.items() if v is not None}
        )
        url = f"{self.api}{path}?{query}" if query else f"{self.api}{path}"
        return _request(url, self.ctx, token=self.token())

    def list_groups(self) -> list[dict]:
        groups = self.get("/customer-groups", {})
        if not isinstance(groups, list):
            raise OrcaError("customer-groups: expected a list")
        return groups

    def _page_snapshots(
        self,
        path: str,
        group: str,
        from_: str,
        to: str | None = None,
        page_size: int = PAGE_SIZE,
    ) -> tuple[list[dict], dict]:
        rows: list[dict] = []
        cursor: str | None = None
        meta: dict = {}
        while True:
            page = self.get(
                path,
                {
                    "group": group,
                    "from": from_,
                    "to": to,
                    "limit": page_size,
                    "cursor": cursor,
                },
            )
            if not isinstance(page, dict):
                raise OrcaError(f"{path}: expected an object")
            if not meta:
                meta = {
                    "from": page.get("from"),
                    "to": page.get("to"),
                }
            rows.extend(page.get("snapshots") or [])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        return rows, meta

    def fetch_snapshots(
        self,
        group: str,
        from_: str,
        to: str | None = None,
        page_size: int = PAGE_SIZE,
    ) -> tuple[list[dict], dict]:
        """Pagina /nav/snapshots (sem posicoes). Retorna (rows, meta da primeira pagina)."""
        return self._page_snapshots("/nav/snapshots", group, from_, to, page_size)

    def fetch_details(
        self,
        group: str,
        from_: str,
        to: str | None = None,
        page_size: int = PAGE_SIZE,
    ) -> tuple[list[dict], dict]:
        """Pagina /nav/snapshots/detail. Retorna (rows, meta da primeira pagina)."""
        return self._page_snapshots("/nav/snapshots/detail", group, from_, to, page_size)

    def list_performance(self, group: str | None = None) -> list[dict]:
        """GET /performance. Um row por customer (ultimo ponto do indice)."""
        params: dict = {}
        if group:
            params["group"] = group
        rows = self.get("/performance", params)
        if not isinstance(rows, list):
            raise OrcaError("performance: expected a list")
        return rows

    def fetch_performance(
        self,
        customer_id: int,
        from_: str | None = None,
    ) -> dict:
        """GET /performance/{id}. Serie horaria do indice (gross/net, equity, flows)."""
        params: dict = {}
        if from_:
            params["from"] = from_
        data = self.get(f"/performance/{customer_id}", params)
        if not isinstance(data, dict):
            raise OrcaError(f"performance/{customer_id}: expected an object")
        return data
