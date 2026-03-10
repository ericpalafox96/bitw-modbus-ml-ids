from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ----------------------------
# Paths
# ----------------------------
REPO_ROOT = Path(__file__).resolve().parents[3]  # repo/src/runtime/dashboard/app.py -> repo is parents[3]
DATA_DIR = REPO_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

LOG_PATH = LOGS_DIR / "ids_events.jsonl"

# ----------------------------
# App + templates/static
# ----------------------------
app = FastAPI(title="BITW Modbus/TCP IDS Dashboard")
BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ----------------------------
# Utilities
# ----------------------------
VALID_CLASSES = {"normal", "timing_attack", "replay_attack", "command_injection"}

def _safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def read_last_jsonl(path: Path, limit: int) -> List[Dict[str, Any]]:
    """
    Reads last `limit` JSON objects from a JSONL file.
    Uses a deque to avoid loading the whole file into memory.
    """
    if not path.exists():
        return []

    dq: deque[str] = deque(maxlen=limit)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            dq.append(line)

    items: List[Dict[str, Any]] = []
    for line in reversed(dq):  # newest first
        obj = _safe_json_loads(line)
        if obj is not None:
            items.append(obj)
    return items

def filter_events(
    items: List[Dict[str, Any]],
    cls: Optional[str],
    min_conf: float,
    since_ts: Optional[float],
) -> List[Dict[str, Any]]:
    out = []
    for e in items:
        pred = e.get("prediction") or e.get("cls")
        conf = float(e.get("confidence", 0.0) or 0.0)
        ts = float(e.get("ts", 0.0) or 0.0)

        if since_ts is not None and ts < since_ts:
            continue
        if cls and pred != cls:
            continue
        if conf < min_conf:
            continue

        out.append(e)
    return out

def now() -> float:
    return time.time()

def summarize(items: List[Dict[str, Any]], seconds: int) -> Dict[str, Any]:
    t = now()
    since = t - seconds
    recent = [e for e in items if float(e.get("ts", 0.0) or 0.0) >= since]

    counts = {c: 0 for c in VALID_CLASSES}
    for e in recent:
        pred = e.get("prediction") or e.get("cls")
        if pred in counts:
            counts[pred] += 1

    total = sum(counts.values())
    attacks = total - counts.get("normal", 0)
    attack_rate = (attacks / total) if total > 0 else 0.0
    top_class = max(counts.items(), key=lambda kv: kv[1])[0] if total > 0 else "n/a"

    return {
        "window_seconds": seconds,
        "events": total,
        "counts": counts,
        "attack_rate": attack_rate,
        "top_class": top_class,
    }

def timeseries(items: List[Dict[str, Any]], seconds: int, bucket: int) -> Dict[str, Any]:
    """
    Returns counts per class in time buckets for the last `seconds`.
    """
    t = now()
    start = t - seconds
    n = int(seconds // bucket)

    series = {c: [0] * n for c in VALID_CLASSES}
    labels = [start + i * bucket for i in range(n)]

    for e in items:
        ts = float(e.get("ts", 0.0) or 0.0)
        if ts < start:
            continue
        idx = int((ts - start) // bucket)
        if 0 <= idx < n:
            pred = e.get("prediction") or e.get("cls")
            if pred in series:
                series[pred][idx] += 1

    return {"start": start, "bucket": bucket, "labels": labels, "series": series}

def find_event_by_id(path: Path, event_id: str, scan_limit_lines: int = 5000) -> Optional[Dict[str, Any]]:
    """
    Finds an event by id by scanning the last `scan_limit_lines` lines.
    (Good enough for MVP without a DB.)
    """
    items = read_last_jsonl(path, limit=scan_limit_lines)
    for e in items:
        if str(e.get("id")) == event_id:
            return e
    return None


# ----------------------------
# Routes
# ----------------------------
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
        "repo_root": str(REPO_ROOT),
    }


@app.get("/api/events")
def api_events(
    limit: int = Query(200, ge=1, le=2000),
    cls: Optional[str] = Query(None),
    min_conf: float = Query(0.0, ge=0.0, le=1.0),
    since_seconds: Optional[int] = Query(None, ge=1, le=3600),
):
    raw = read_last_jsonl(LOG_PATH, limit=limit)
    since_ts = (now() - since_seconds) if since_seconds else None
    items = filter_events(raw, cls=cls, min_conf=min_conf, since_ts=since_ts)

    # ensure newest first
    items = sorted(items, key=lambda e: float(e.get("ts", 0.0) or 0.0), reverse=True)

    # reduce payload for table
    table_items = []
    for e in items:
        table_items.append({
            "id": e.get("id"),
            "ts": e.get("ts"),
            "prediction": e.get("prediction") or e.get("cls"),
            "confidence": e.get("confidence"),
            "policy_action": e.get("policy_action", ""),
            "src_ip": e.get("src_ip"),
            "dst_ip": e.get("dst_ip"),
            "src_port": e.get("src_port"),
            "dst_port": e.get("dst_port", 502),
        })

    return {"items": table_items, "total": len(table_items)}


@app.get("/api/summary")
def api_summary():
    # read a reasonable buffer for stats
    items = read_last_jsonl(LOG_PATH, limit=5000)
    s1 = summarize(items, 60)
    s5 = summarize(items, 300)
    s15 = summarize(items, 900)
    return {"last_1m": s1, "last_5m": s5, "last_15m": s15}


@app.get("/api/timeseries")
def api_timeseries(
    seconds: int = Query(600, ge=60, le=3600),
    bucket: int = Query(10, ge=1, le=60),
):
    items = read_last_jsonl(LOG_PATH, limit=10000)
    return timeseries(items, seconds=seconds, bucket=bucket)


@app.get("/api/event/{event_id}")
def api_event_detail(event_id: str):
    e = find_event_by_id(LOG_PATH, event_id=event_id, scan_limit_lines=8000)
    if not e:
        return JSONResponse({"error": "not found"}, status_code=404)

    feats = e.get("features") or {}
    if isinstance(feats, dict):
        top_feats = sorted(feats.items(), key=lambda kv: abs(float(kv[1])) if kv[1] is not None else 0.0, reverse=True)[:10]
    else:
        top_feats = []

    return {
        "id": e.get("id"),
        "ts": e.get("ts"),
        "prediction": e.get("prediction") or e.get("cls"),
        "confidence": e.get("confidence"),
        "policy_action": e.get("policy_action", ""),
        "src_ip": e.get("src_ip"),
        "dst_ip": e.get("dst_ip"),
        "src_port": e.get("src_port"),
        "dst_port": e.get("dst_port", 502),
        "window_seconds": e.get("window_seconds", 0.5),
        "model": e.get("model", {}),
        "top_features": [{"name": k, "value": v} for k, v in top_feats],
        "features": feats,
    }


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()

    # Start tailing from end of file so we only stream new events
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
                        await ws.send_text(json.dumps(obj))

            await asyncio.sleep(0.2)

    except WebSocketDisconnect:
        return
    except Exception:
        return