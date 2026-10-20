---
arquivo_original: "orca_to_supa.py"
caminho_deal: "Orca"
mime_type: "text/x-python-script"
data_conversao: "2026-10-20T23:01:26.154Z"
---

"""
Collector ORCA -> Supabase (feed do app hospedado).

O que este script faz:
  - Puxa snapshots horarios do grupo ORCA (VPN / phi.env).
  - Grava pl_snapshots, holdings_snapshots e orders_history no Supabase.
  - Publica o dump JSON em Storage (orca-feed/b1.json) a partir das tabelas,
    nao do payload cru da ORCA, para o app ver todos os portfolios.
  - Roda um ciclo e dorme INTERVAL_SEC (default 5 min). Use --once para um ciclo.

Variaveis:
  - ORCA_GROUP          default B1
  - ORCA_CLIENT_CODE    default VEBEL_REAL (portfolio reservado)
  - PORTFOLIO_ID        uuid do cliente padrao (VEBEL_REAL)
  - SUPABASE_URL / VITE_SUPABASE_URL
  - SUPABASE_SERVICE_ROLE_KEY
  - --days              janela (default 30)
  - --interval          segundos entre ciclos (default 300)

Regras fixas:
  - VEBEL_REAL vai para PORTFOLIO_ID. Outros customers ganham uuid5 estavel.
  - Ordens sao diffs de quantidade entre horas, nao fills da venue.
  - Apaga a janela daquele portfolio e reinsere (fonte da verdade = ORCA).
  - Nao imprime secrets. Nao grava Coinbase.
  - Pare o collector Coinbase no outro PC antes de deixar isto rodando.

Uso (venv):
  .\\venv\\Scripts\\python.exe orca_to_supa.py --from-db
  .\\venv\\Scripts\\python.exe orca_to_supa.py --once
  .\\venv\\Scripts\\python.exe orca_to_supa.py
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
ONLINE_ROOT = ROOT / "online_version"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")
load_dotenv(ONLINE_ROOT / ".env")

from orca_client import OrcaClient, OrcaError
from orca_fetch_cli import customers_from_snapshots, movements_from_snapshots, slim_snapshot

log = logging.getLogger("orca_to_supa")

ORCA_GROUP = os.environ.get("ORCA_GROUP", "B1")
ORCA_CLIENT_CODE = os.environ.get("ORCA_CLIENT_CODE", "VEBEL_REAL")
DEFAULT_PORTFOLIO_ID = "c011e000-0000-4000-8000-000000000001"
NS = uuid.UUID(DEFAULT_PORTFOLIO_ID)
Q8 = Decimal("0.00000001")
BATCH = 200
DELETE_BATCH = 500
FEED_BUCKET = "orca-feed"
FEED_OBJECT = "b1.json"


def _dec(value) -> Decimal:
    if value is None:
        return Decimal("0")
    text = str(value).strip()
    if not text or text.lower() in {"none", "nan", "null"}:
        return Decimal("0")
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return Decimal("0")


def q8(value) -> float:
    return float(_dec(value).quantize(Q8, rounding=ROUND_HALF_UP))


def default_portfolio_id() -> str:
    return os.environ.get("PORTFOLIO_ID") or DEFAULT_PORTFOLIO_ID


def portfolio_id_for(code: str) -> str:
    if code == ORCA_CLIENT_CODE:
        return default_portfolio_id()
    return str(uuid.uuid5(NS, code))


def _supabase():
    from supabase import create_client

    url = os.environ.get("SUPABASE_URL") or os.environ.get("VITE_SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise RuntimeError("Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY")
    return create_client(url, key)


def _chunks(rows: list, size: int):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def ensure_portfolio(sb, pid: str, nome: str) -> None:
    found = sb.table("portfolios").select("id").eq("id", pid).limit(1).execute()
    if found.data:
        return
    sb.table("portfolios").insert({"id": pid, "nome": nome}).execute()


def wipe_window(sb, table: str, pid: str, from_iso: str) -> int:
    total = 0
    while True:
        rows = (
            sb.table(table)
            .select("id")
            .eq("portfolio_id", pid)
            .gte("timestamp_utc", from_iso)
            .limit(DELETE_BATCH)
            .execute()
        )
        ids = [str(r["id"]) for r in (rows.data or [])]
        if not ids:
            return total
        sb.table(table).delete().in_("id", ids).execute()
        total += len(ids)
        if len(ids) < DELETE_BATCH:
            return total


def insert_rows(sb, table: str, rows: list[dict]) -> int:
    n = 0
    for chunk in _chunks(rows, BATCH):
        sb.table(table).insert(chunk).execute()
        n += len(chunk)
    return n


def pl_payloads(snaps: list[dict], pid: str) -> list[dict]:
    by_hour: dict[str, list[dict]] = {}
    for snap in snaps:
        hour = str(snap.get("as_of_hour") or "")
        if hour:
            by_hour.setdefault(hour, []).append(snap)
    out: list[dict] = []
    for hour, group in sorted(by_hour.items()):
        usd = sum((_dec(s.get("equity_usd")) for s in group), Decimal("0"))
        brl_vals = [
            _dec(s.get("equity_brl"))
            for s in group
            if s.get("equity_brl") not in (None, "")
        ]
        brl = sum(brl_vals, Decimal("0")) if brl_vals else Decimal("0")
        out.append(
            {
                "portfolio_id": pid,
                "timestamp_utc": hour,
                "pl_bruto": q8(brl),
                "taxa_adm_dia": 0,
                "pl_pos_adm": q8(usd),
                "cota_pre_pfee": 1,
                "hwm_atual": 1,
                "excedente": 0,
                "pfee_prov": 0,
                "pl_final": q8(usd),
                "cotas_em_circ": 1,
                "cota_final": 1,
                "fluxo_detectado": 0,
                "is_fechamento_dia": False,
            }
        )
    return out


def holding_payloads(snaps: list[dict], pid: str) -> list[dict]:
    rows: list[dict] = []
    for snap in snaps:
        hour = str(snap.get("as_of_hour") or "")
        if not hour:
            continue
        for pos in snap.get("positions") or []:
            asset = str(pos.get("asset") or "").strip()
            if not asset:
                continue
            rows.append(
                {
                    "portfolio_id": pid,
                    "timestamp_utc": hour,
                    "asset": asset,
                    "quantidade": q8(pos.get("quantity")),
                    "preco": q8(pos.get("rate_usd")),
                    "valor": q8(pos.get("value_usd")),
                    "peso_pct": q8(pos.get("peso_pct")),
                }
            )
    return rows


def order_payloads(moves: list[dict], pid: str, code: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for m in moves:
        if str(m.get("customer_code") or "") != code:
            continue
        hour = str(m.get("as_of_hour") or "")
        asset = str(m.get("asset") or "")
        side = str(m.get("side") or "")
        venue = str(m.get("venue_code") or "")
        fill_id = f"{m.get('from_hour')}|{hour}|{venue}|{asset}|{side}"
        if fill_id in seen:
            continue
        seen.add(fill_id)
        rows.append(
            {
                "portfolio_id": pid,
                "order_id": f"{code}|{hour}|{asset}|{side}",
                "timestamp_utc": hour,
                "product_id": asset,
                "side": side,
                "order_type": "Posicao",
                "status": str(m.get("status") or "—"),
                "price_execucao": q8(m.get("preco_usd") or "0"),
                "quantidade": q8(m.get("quantidade")),
                "valor_total": q8(m.get("valor_usd") or "0"),
                "fee": 0,
                "fill_id": fill_id,
            }
        )
    return rows


def sync_once(group: str, days: int) -> None:
    start = (datetime.now(timezone.utc) - timedelta(days=days)).replace(
        minute=0, second=0, microsecond=0
    )
    from_iso = start.strftime("%Y-%m-%dT%H:00:00Z")
    client = OrcaClient()
    raw, meta = client.fetch_details(group, from_iso)
    snaps = [slim_snapshot(r) for r in raw]
    moves = movements_from_snapshots(snaps)
    customers = customers_from_snapshots(snaps)
    if not customers:
        customers = [{"code": ORCA_CLIENT_CODE, "name": ORCA_CLIENT_CODE}]

    sb = _supabase()
    log.info(
        "ORCA %s from=%s snapshots=%s movements=%s customers=%s",
        group,
        meta.get("from") or from_iso,
        len(snaps),
        len(moves),
        ",".join(c["code"] for c in customers),
    )

    for customer in customers:
        code = str(customer["code"])
        nome = str(customer.get("name") or code)
        pid = portfolio_id_for(code)
        ensure_portfolio(sb, pid, nome)
        own = [s for s in snaps if s.get("customer_code") == code]
        pl = pl_payloads(own, pid)
        holdings = holding_payloads(own, pid)
        orders = order_payloads(moves, pid, code)
        n_pl = wipe_window(sb, "pl_snapshots", pid, from_iso)
        n_h = wipe_window(sb, "holdings_snapshots", pid, from_iso)
        n_o = wipe_window(sb, "orders_history", pid, from_iso)
        insert_rows(sb, "pl_snapshots", pl)
        insert_rows(sb, "holdings_snapshots", holdings)
        insert_rows(sb, "orders_history", orders)
        log.info(
            "%s -> %s  pl %s->%s  holdings %s->%s  orders %s->%s",
            code,
            pid,
            n_pl,
            len(pl),
            n_h,
            len(holdings),
            n_o,
            len(orders),
        )

    payload = dump_from_db(sb, from_iso, group, meta)
    publish_dump(sb, payload)


def _paged_since(sb, table: str, cols: str, from_iso: str) -> list:
    out = []
    start = 0
    while True:
        res = (
            sb.table(table)
            .select(cols)
            .gte("timestamp_utc", from_iso)
            .order("timestamp_utc")
            .range(start, start + BATCH - 1)
            .execute()
        )
        chunk = res.data or []
        out.extend(chunk)
        if len(chunk) < BATCH:
            return out
        start += BATCH


def dump_from_db(sb, from_iso: str, group: str, meta: dict | None = None) -> dict:
    """Monta o JSON publico a partir das tabelas (service role ve todos os portfolios)."""
    ports = sb.table("portfolios").select("id, nome").execute().data or []
    nome_by_pid = {str(p["id"]): str(p.get("nome") or p["id"]) for p in ports}
    customers = [{"code": pid, "name": nome} for pid, nome in nome_by_pid.items()]

    pl_rows = _paged_since(
        sb,
        "pl_snapshots",
        "portfolio_id,timestamp_utc,pl_final,pl_bruto",
        from_iso,
    )
    holding_rows = _paged_since(
        sb,
        "holdings_snapshots",
        "portfolio_id,timestamp_utc,asset,quantidade,preco,valor,peso_pct",
        from_iso,
    )
    order_rows = _paged_since(
        sb,
        "orders_history",
        "portfolio_id,timestamp_utc,product_id,side,quantidade,price_execucao,valor_total,status,fill_id",
        from_iso,
    )

    pos_by_key: dict[tuple, list] = {}
    for h in holding_rows:
        pid = str(h.get("portfolio_id") or "")
        ts = str(h.get("timestamp_utc") or "")
        if not pid or not ts:
            continue
        pos_by_key.setdefault((pid, ts), []).append(
            {
                "asset": h.get("asset"),
                "quantity": str(h.get("quantidade") or "0"),
                "rate_usd": str(h.get("preco") or "0"),
                "value_usd": str(h.get("valor") or "0"),
                "peso_pct": str(h.get("peso_pct") or "0"),
            }
        )

    snaps = []
    for row in pl_rows:
        pid = str(row.get("portfolio_id") or "")
        ts = str(row.get("timestamp_utc") or "")
        if not pid or not ts:
            continue
        equity = str(row.get("pl_final") or "0")
        brl = row.get("pl_bruto")
        snaps.append(
            {
                "as_of_hour": ts,
                "customer_code": pid,
                "customer_name": nome_by_pid.get(pid, pid),
                "venue_code": "DB",
                "equity_usd": equity,
                "equity_brl": None if brl is None else str(brl),
                "usd_brl_rate": None,
                "status": "ok",
                "positions": pos_by_key.get((pid, ts), []),
            }
        )

    moves = []
    for o in order_rows:
        pid = str(o.get("portfolio_id") or "")
        ts = str(o.get("timestamp_utc") or "")
        if not pid or not ts:
            continue
        moves.append(
            {
                "customer_code": pid,
                "customer_name": nome_by_pid.get(pid, pid),
                "venue_code": "DB",
                "as_of_hour": ts,
                "from_hour": ts,
                "asset": o.get("product_id"),
                "side": o.get("side"),
                "quantidade": str(o.get("quantidade") or "0"),
                "preco_usd": str(o.get("price_execucao") or "0"),
                "valor_usd": str(o.get("valor_total") or "0"),
                "status": o.get("status") or "—",
            }
        )

    return {
        "group": group,
        "from": (meta or {}).get("from") or from_iso,
        "to": (meta or {}).get("to"),
        "customers": customers,
        "snapshots": snaps,
        "movements": moves,
    }


def publish_dump(sb, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    try:
        sb.storage.create_bucket(FEED_BUCKET, options={"public": True})
    except Exception:
        pass
    opts = {
        "content-type": "application/json",
        "upsert": "true",
        "cache-control": "max-age=60",
    }
    bucket = sb.storage.from_(FEED_BUCKET)
    try:
        bucket.remove([FEED_OBJECT])
    except Exception:
        pass
    try:
        bucket.upload(FEED_OBJECT, raw, opts)
    except Exception:
        bucket.update(FEED_OBJECT, raw, opts)
    log.info("Dump publicado: %s/%s (%s bytes)", FEED_BUCKET, FEED_OBJECT, len(raw))


def main() -> int:
    parser = argparse.ArgumentParser(description="ORCA NAV -> Supabase")
    parser.add_argument("--group", default=ORCA_GROUP)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Republica o dump a partir das tabelas, sem puxar a ORCA",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.from_db:
        start = (datetime.now(timezone.utc) - timedelta(days=args.days)).replace(
            minute=0, second=0, microsecond=0
        )
        from_iso = start.strftime("%Y-%m-%dT%H:00:00Z")
        sb = _supabase()
        payload = dump_from_db(sb, from_iso, args.group)
        publish_dump(sb, payload)
        return 0

    while True:
        try:
            sync_once(args.group, args.days)
        except OrcaError as exc:
            log.error("ORCA: %s", exc)
            if args.once:
                return 1
        except Exception:
            log.exception("Falha no ciclo")
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(max(60, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
