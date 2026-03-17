from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from runtime.dashboard.note_store import get_event_note, set_event_note
from runtime.dashboard.report_utils import summarize_events
from runtime.dashboard.export_utils import events_to_csv

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

LOG_PATH = LOGS_DIR / "ids_events.jsonl"

app = FastAPI(title="BITW Modbus/TCP IDS Dashboard")
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

VALID_CLASSES = {"normal", "timing_attack", "replay_attack", "command_injection"}

SEVERITY_MAP = {
    "normal": "info",
    "timing_attack": "medium",
    "replay_attack": "high",
    "command_injection": "critical",
}

RESPONSE_MAP = {
    "normal": "No action required. Continue monitoring traffic baseline.",
    "timing_attack": "Inspect burst timing anomalies and validate repeated polling behavior from the controller.",
    "replay_attack": "Review repeated Modbus exchanges and verify session legitimacy before restoring trust.",
    "command_injection": "Treat as critical. Validate command source, inspect recent control traffic, and verify operator authenticity.",
}


def now() -> float:
    return time.time()


def _safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def read_last_jsonl(path: Path, limit: int) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    dq: deque[str] = deque(maxlen=limit)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            dq.append(line)

    items: List[Dict[str, Any]] = []
    for line in reversed(dq):
        obj = _safe_json_loads(line)
        if obj is not None:
            items.append(obj)
    return items


def read_last_jsonl_object(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None

    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return None

            chunk_size = 2048
            buf = b""
            pos = end

            while pos > 0:
                step = min(chunk_size, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step)
                buf = data + buf
                if b"\n" in data and pos != 0:
                    break

            lines = [ln.strip() for ln in buf.splitlines() if ln.strip()]
            if not lines:
                return None

            return _safe_json_loads(lines[-1].decode("utf-8", errors="ignore"))
    except Exception:
        return None


def enrich_event(e: Dict[str, Any]) -> Dict[str, Any]:
    pred = e.get("prediction") or e.get("cls") or "unknown"
    severity = e.get("severity") or SEVERITY_MAP.get(pred, "unknown")
    response = e.get("recommended_response") or RESPONSE_MAP.get(pred, "Review event details.")
    features = e.get("features") or {}

    out = dict(e)
    out["prediction"] = pred
    out["severity"] = severity
    out["recommended_response"] = response

    note_meta = get_event_note(str(out.get("id"))) if out.get("id") else {}
    out["status"] = note_meta.get("status", out.get("status", "new"))
    out["analyst_note"] = note_meta.get("note", "")

    out["protocol"] = out.get("protocol", "modbus_tcp")
    out["features"] = features if isinstance(features, dict) else {}
    return out


def filter_events(
    items: List[Dict[str, Any]],
    cls: Optional[str],
    min_conf: float,
    since_ts: Optional[float],
    q: Optional[str],
) -> List[Dict[str, Any]]:
    out = []
    q_norm = q.lower().strip() if q else None

    for raw in items:
        e = enrich_event(raw)
        pred = e["prediction"]
        conf = float(e.get("confidence", 0.0) or 0.0)
        ts = float(e.get("ts", 0.0) or 0.0)

        if since_ts is not None and ts < since_ts:
            continue
        if cls and pred != cls:
            continue
        if conf < min_conf:
            continue

        if q_norm:
            haystack = " ".join([
                str(e.get("prediction", "")),
                str(e.get("severity", "")),
                str(e.get("policy_action", "")),
                str(e.get("src_ip", "")),
                str(e.get("dst_ip", "")),
                str(e.get("src_port", "")),
                str(e.get("dst_port", "")),
                str(e.get("protocol", "")),
                str(e.get("status", "")),
            ]).lower()
            if q_norm not in haystack:
                continue

        out.append(e)

    return out


def summarize(items: List[Dict[str, Any]], seconds: int) -> Dict[str, Any]:
    t = now()
    since = t - seconds
    recent = [enrich_event(e) for e in items if float(e.get("ts", 0.0) or 0.0) >= since]

    counts = {c: 0 for c in VALID_CLASSES}
    severity_counts = {"info": 0, "medium": 0, "high": 0, "critical": 0}

    for e in recent:
        pred = e["prediction"]
        sev = e["severity"]
        if pred in counts:
            counts[pred] += 1
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = sum(counts.values())
    attacks = total - counts.get("normal", 0)
    attack_rate = (attacks / total) if total > 0 else 0.0
    top_class = max(counts.items(), key=lambda kv: kv[1])[0] if total > 0 else "n/a"

    return {
        "window_seconds": seconds,
        "events": total,
        "counts": counts,
        "severity_counts": severity_counts,
        "attack_rate": attack_rate,
        "top_class": top_class,
    }


def timeseries(items: List[Dict[str, Any]], seconds: int, bucket: int) -> Dict[str, Any]:
    t = now()
    start = t - seconds
    n = int(seconds // bucket)

    series = {c: [0] * n for c in VALID_CLASSES}
    labels = [start + i * bucket for i in range(n)]

    for raw in items:
        e = enrich_event(raw)
        ts = float(e.get("ts", 0.0) or 0.0)
        if ts < start:
            continue
        idx = int((ts - start) // bucket)
        if 0 <= idx < n:
            pred = e["prediction"]
            if pred in series:
                series[pred][idx] += 1

    return {"start": start, "bucket": bucket, "labels": labels, "series": series}


def find_event_by_id(path: Path, event_id: str, scan_limit_lines: int = 8000) -> Optional[Dict[str, Any]]:
    items = read_last_jsonl(path, limit=scan_limit_lines)
    for e in items:
        if str(e.get("id")) == event_id:
            return enrich_event(e)
    return None


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
def health():
    exists = LOG_PATH.exists()
    size = LOG_PATH.stat().st_size if exists else 0
    return {
        "status": "ok",
        "log_path": str(LOG_PATH),
        "log_exists": exists,
        "log_bytes": size,
    }


@app.get("/api/log_status")
def log_status():
    exists = LOG_PATH.exists()
    size = LOG_PATH.stat().st_size if exists else 0

    last = read_last_jsonl_object(LOG_PATH)
    if not last:
        return {
            "log_exists": exists,
            "log_bytes": size,
            "last_event_ts": None,
            "last_event_age_sec": None,
            "last_event_id": None,
            "last_prediction": None,
            "last_confidence": None,
        }

    last = enrich_event(last)
    ts = float(last.get("ts", 0.0) or 0.0)
    age = now() - ts if ts > 0 else None

    return {
        "log_exists": exists,
        "log_bytes": size,
        "last_event_ts": ts if ts > 0 else None,
        "last_event_age_sec": float(age) if age is not None else None,
        "last_event_id": last.get("id"),
        "last_prediction": last.get("prediction"),
        "last_confidence": last.get("confidence"),
    }


@app.get("/api/events")
def api_events(
    limit: int = Query(500, ge=1, le=5000),
    cls: Optional[str] = Query(None),
    min_conf: float = Query(0.0, ge=0.0, le=1.0),
    since_seconds: Optional[int] = Query(None, ge=1, le=86400),
    q: Optional[str] = Query(None),
):
    raw = read_last_jsonl(LOG_PATH, limit=limit)
    since_ts = (now() - since_seconds) if since_seconds else None
    items = filter_events(raw, cls=cls, min_conf=min_conf, since_ts=since_ts, q=q)
    items = sorted(items, key=lambda e: float(e.get("ts", 0.0) or 0.0), reverse=True)

    table_items = []
    for e in items:
        table_items.append({
            "id": e.get("id"),
            "ts": e.get("ts"),
            "prediction": e.get("prediction"),
            "severity": e.get("severity"),
            "confidence": e.get("confidence"),
            "policy_action": e.get("policy_action", ""),
            "status": e.get("status", "new"),
            "protocol": e.get("protocol", "modbus_tcp"),
            "src_ip": e.get("src_ip"),
            "dst_ip": e.get("dst_ip"),
            "src_port": e.get("src_port"),
            "dst_port": e.get("dst_port", 502),
        })

    return {"items": table_items, "total": len(table_items)}


@app.get("/api/summary")
def api_summary():
    items = read_last_jsonl(LOG_PATH, limit=8000)
    return {
        "last_1m": summarize(items, 60),
        "last_5m": summarize(items, 300),
        "last_15m": summarize(items, 900),
    }


@app.get("/api/timeseries")
def api_timeseries(
    seconds: int = Query(600, ge=60, le=3600),
    bucket: int = Query(10, ge=1, le=60),
):
    items = read_last_jsonl(LOG_PATH, limit=10000)
    return timeseries(items, seconds=seconds, bucket=bucket)


@app.get("/api/event/{event_id}")
def api_event_detail(event_id: str):
    e = find_event_by_id(LOG_PATH, event_id=event_id)
    if not e:
        return JSONResponse({"error": "not found"}, status_code=404)

    feats = e.get("features") or {}
    top_feats = sorted(
        feats.items(),
        key=lambda kv: abs(float(kv[1])) if kv[1] is not None else 0.0,
        reverse=True
    )[:12]

    return {
        "id": e.get("id"),
        "ts": e.get("ts"),
        "prediction": e.get("prediction"),
        "severity": e.get("severity"),
        "confidence": e.get("confidence"),
        "policy_action": e.get("policy_action", ""),
        "status": e.get("status", "new"),
        "protocol": e.get("protocol", "modbus_tcp"),
        "src_ip": e.get("src_ip"),
        "dst_ip": e.get("dst_ip"),
        "src_port": e.get("src_port"),
        "dst_port": e.get("dst_port", 502),
        "window_seconds": e.get("window_seconds", 0.5),
        "model": e.get("model", {}),
        "recommended_response": e.get("recommended_response"),
        "top_features": [{"name": k, "value": v} for k, v in top_feats],
        "features": feats,
        "analyst_note": e.get("analyst_note", ""),
    }


@app.get("/api/report")
def api_report(window: int = Query(900, ge=60, le=86400)):
    items = read_last_jsonl(LOG_PATH, limit=15000)
    recent = [
        enrich_event(e)
        for e in items
        if float(e.get("ts", 0.0) or 0.0) >= now() - window
    ]

    summary = summarize_events(recent, VALID_CLASSES)

    return {
        "window": window,
        "summary": summary,
        "top_sources": summary["top_sources"],
        "average_confidence": summary["average_confidence"],
        "most_recent_prediction": summary["most_recent_prediction"],
    }


@app.get("/api/export/events.csv")
def export_events_csv(
    limit: int = Query(1000, ge=1, le=10000),
    cls: Optional[str] = Query(None),
    min_conf: float = Query(0.0, ge=0.0, le=1.0),
    since_seconds: Optional[int] = Query(None, ge=1, le=86400),
    q: Optional[str] = Query(None),
):
    raw = read_last_jsonl(LOG_PATH, limit=limit)
    since_ts = (now() - since_seconds) if since_seconds else None
    items = filter_events(raw, cls=cls, min_conf=min_conf, since_ts=since_ts, q=q)
    items = sorted(items, key=lambda e: float(e.get("ts", 0.0) or 0.0), reverse=True)

    csv_text = events_to_csv(items)

    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ids_events.csv"},
    )


@app.get("/api/event/{event_id}/note")
def api_get_event_note(event_id: str):
    return get_event_note(event_id)


@app.post("/api/event/{event_id}/note")
async def api_set_event_note(event_id: str, request: Request):
    body = await request.json()
    note = body.get("note")
    status = body.get("status")
    saved = set_event_note(event_id, note=note, status=status)
    return {"ok": True, "event_id": event_id, "saved": saved}


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    pos = 0
    if LOG_PATH.exists():
        pos = LOG_PATH.stat().st_size

    try:
        while True:
            if not LOG_PATH.exists():
                await asyncio.sleep(0.5)
                continue

            with open(LOG_PATH, "r", encoding="utf-8") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()

            if chunk:
                for line in chunk.splitlines():
                    obj = _safe_json_loads(line)
                    if obj is not None:
                        await ws.send_text(json.dumps(enrich_event(obj)))

            await asyncio.sleep(0.2)

    except WebSocketDisconnect:
        return
    except Exception:
        return