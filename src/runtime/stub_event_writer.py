import json
import random
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_PATH = REPO_ROOT / "data" / "logs" / "ids_events.jsonl"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

CLASSES = ["normal", "timing_attack", "replay_attack", "command_injection"]

POLICY_MAP = {
    "normal": "forward",
    "timing_attack": "alert",
    "replay_attack": "terminate_session",
    "command_injection": "drop_packet",
}

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


def make_features(cls: str) -> dict:
    if cls == "normal":
        return {
            "packet_count": random.randint(8, 25),
            "bytes_total": random.randint(500, 6000),
            "iat_mean": round(random.uniform(0.01, 0.05), 6),
            "iat_std": round(random.uniform(0.001, 0.01), 6),
            "packet_size_mean": round(random.uniform(60, 180), 3),
        }

    if cls == "timing_attack":
        return {
            "packet_count": random.randint(20, 60),
            "bytes_total": random.randint(2000, 12000),
            "iat_mean": round(random.uniform(0.0005, 0.005), 6),
            "iat_std": round(random.uniform(0.0001, 0.002), 6),
            "packet_size_mean": round(random.uniform(70, 200), 3),
        }

    if cls == "replay_attack":
        return {
            "packet_count": random.randint(25, 80),
            "bytes_total": random.randint(4000, 18000),
            "iat_mean": round(random.uniform(0.002, 0.012), 6),
            "iat_std": round(random.uniform(0.0005, 0.004), 6),
            "packet_size_mean": round(random.uniform(90, 260), 3),
        }

    return {
        "packet_count": random.randint(10, 35),
        "bytes_total": random.randint(1500, 9000),
        "iat_mean": round(random.uniform(0.001, 0.008), 6),
        "iat_std": round(random.uniform(0.0003, 0.003), 6),
        "packet_size_mean": round(random.uniform(100, 320), 3),
    }


def make_confidence(cls: str) -> float:
    if cls == "normal":
        return round(random.uniform(0.65, 0.92), 3)
    if cls == "timing_attack":
        return round(random.uniform(0.78, 0.95), 3)
    if cls == "replay_attack":
        return round(random.uniform(0.82, 0.97), 3)
    return round(random.uniform(0.88, 0.99), 3)


def make_event() -> dict:
    cls = random.choices(
        CLASSES,
        weights=[0.70, 0.12, 0.10, 0.08],
        k=1
    )[0]

    return {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "window_seconds": 0.5,
        "prediction": cls,
        "confidence": make_confidence(cls),
        "severity": SEVERITY_MAP[cls],
        "policy_action": POLICY_MAP[cls],
        "status": "new",
        "protocol": "modbus_tcp",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": random.randint(50000, 59999),
        "dst_port": 502,
        "features": make_features(cls),
        "model": {
            "name": "rf_4class.pkl",
            "version": "stub"
        },
        "recommended_response": RESPONSE_MAP[cls],
    }


if __name__ == "__main__":
    print(f"Writing events to: {LOG_PATH}")
    while True:
        event = make_event()
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        time.sleep(0.5)