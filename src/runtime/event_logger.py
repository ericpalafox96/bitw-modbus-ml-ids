import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

# repo_root/.../data/logs/ids_events.jsonl
REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = REPO_ROOT / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "ids_events.jsonl"

def log_event(
    prediction: str,
    confidence: float,
    features: Dict[str, float],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = 502,
    policy_action: str = "forward",
    model_name: str = "rf_4class.pkl",
    window_seconds: float = 0.5,
) -> Dict[str, Any]:
    event = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "window_seconds": window_seconds,
        "prediction": prediction,
        "confidence": float(confidence),
        "policy_action": policy_action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "features": features,
        "model": {"name": model_name},
    }

    # append JSONL (one JSON per line)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    return event