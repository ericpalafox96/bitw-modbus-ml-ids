import json, time, uuid, random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_PATH = REPO_ROOT / "data" / "logs" / "ids_events.jsonl"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

CLASSES = ["normal", "timing_attack", "replay_attack", "command_injection"]
POLICY = {
    "normal": "forward",
    "timing_attack": "alert",
    "replay_attack": "terminate_session",
    "command_injection": "drop_packet",
}

def make_event():
    cls = random.choices(CLASSES, weights=[0.75, 0.10, 0.10, 0.05])[0]
    conf = round(random.uniform(0.80, 0.99) if cls != "normal" else random.uniform(0.60, 0.95), 3)

    return {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "window_seconds": 0.5,
        "prediction": cls,
        "confidence": conf,
        "policy_action": POLICY[cls],
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000 + random.randint(0, 9999),
        "dst_port": 502,
        "features": {
            "packet_count": random.randint(5, 80),
            "bytes_total": random.randint(300, 50000),
            "iat_mean": random.uniform(0.0005, 0.02),
        },
        "model": {"name": "rf_4class.pkl", "version": "stub"},
    }

if __name__ == "__main__":
    print(f"Writing events to: {LOG_PATH}")
    while True:
        e = make_event()
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n")
        time.sleep(0.5)