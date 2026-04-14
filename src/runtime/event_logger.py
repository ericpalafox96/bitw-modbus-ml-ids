import json
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = REPO_ROOT / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "ids_events.jsonl"

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

JETSON_IP = "192.168.50.5"


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
    model_version: str = "v1",
    window_seconds: float = 0.5,
    protocol: str = "modbus_tcp",
    status: str = "new",
) -> Dict[str, Any]:
    severity = SEVERITY_MAP.get(prediction, "unknown")
    recommended_response = RESPONSE_MAP.get(prediction, "Review event details.")

    event = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "window_seconds": window_seconds,
        "prediction": prediction,
        "confidence": float(confidence),
        "severity": severity,
        "policy_action": policy_action,
        "status": status,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sensor_ip": JETSON_IP,
        "src_port": src_port,
        "dst_port": dst_port,
        "features": features,
        "model": {
            "name": model_name,
            "version": model_version,
        },
        "recommended_response": recommended_response,
    }

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()

    return event