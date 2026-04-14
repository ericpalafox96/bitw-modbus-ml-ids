from __future__ import annotations

import argparse
import ipaddress
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import joblib
import numpy as np
from scapy.all import IP, TCP, Raw, sniff  # type: ignore

from runtime.event_logger import log_event


REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "rf_4class.pkl"

# Must match training CSV column order exactly.
FEATURE_COLUMNS = [
    "packet_count",
    "bytes_total",
    "packet_size_mean",
    "packet_size_std",
    "iat_mean",
    "iat_std",
    "dup_payload_ratio",
    "write_ratio",
    "unique_write_regs",
]

VALID_CLASSES = {"normal", "timing_attack", "replay_attack", "command_injection"}


class PacketWindowBuffer:
    def __init__(self, window_seconds: float = 0.5) -> None:
        self.window_seconds = window_seconds
        self.buffer: Deque[Dict[str, Any]] = deque()

    def add_packet(self, pkt_info: Dict[str, Any]) -> None:
        self.buffer.append(pkt_info)
        self._evict_old(pkt_info["ts"])

    def _evict_old(self, current_ts: float) -> None:
        cutoff = current_ts - self.window_seconds
        while self.buffer and self.buffer[0]["ts"] < cutoff:
            self.buffer.popleft()

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self.buffer)


def safe_std(values: List[float]) -> float:
    if len(values) <= 1:
        return 0.0
    return float(np.std(values))


def safe_mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(np.mean(values))


def payload_to_hex(payload: bytes, max_len: int = 64) -> str:
    return payload[:max_len].hex()


def parse_modbus_function_code(payload: bytes) -> Optional[int]:
    # MBAP header is 7 bytes:
    # transaction id (2), protocol id (2), length (2), unit id (1)
    # function code follows at byte index 7
    if len(payload) < 8:
        return None
    return int(payload[7])


def parse_modbus_register_address(payload: bytes, function_code: int) -> Optional[int]:
    # For common Modbus read/write functions, starting/register address is bytes 8:10
    if len(payload) < 10:
        return None

    if function_code in {1, 2, 3, 4, 5, 6, 15, 16}:
        return int.from_bytes(payload[8:10], byteorder="big", signed=False)

    return None


def is_modbus_response(src_port: int, dst_port: int) -> bool:
    return src_port == 502


def is_modbus_request(src_port: int, dst_port: int) -> bool:
    return dst_port == 502


def packet_to_info(pkt: Any) -> Optional[Dict[str, Any]]:
    if IP not in pkt or TCP not in pkt:
        return None

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]

    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    src_port = int(tcp_layer.sport)
    dst_port = int(tcp_layer.dport)

    # Restrict to Modbus/TCP
    if src_port != 502 and dst_port != 502:
        return None

    raw_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""
    ts = float(pkt.time)
    pkt_len = int(len(pkt))
    fn_code = parse_modbus_function_code(raw_bytes) if raw_bytes else None

    return {
        "ts": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": pkt_len,
        "payload_len": len(raw_bytes),
        "payload_hex": payload_to_hex(raw_bytes),
        "raw_bytes": raw_bytes,
        "function_code": fn_code,
        "is_request": is_modbus_request(src_port, dst_port),
        "is_response": is_modbus_response(src_port, dst_port),
    }


def build_features(window_packets: List[Dict[str, Any]]) -> Dict[str, float]:
    if not window_packets:
        return {name: 0.0 for name in FEATURE_COLUMNS}

    lengths = [float(p["length"]) for p in window_packets]
    timestamps = [float(p["ts"]) for p in window_packets]

    interarrivals: List[float] = []
    for i in range(1, len(timestamps)):
        interarrivals.append(max(0.0, timestamps[i] - timestamps[i - 1]))

    payloads: List[str] = []
    write_request_count = 0
    write_registers = set()

    for p in window_packets:
        payloads.append(p["payload_hex"])

        fn = p.get("function_code")
        if p["is_request"] and fn is not None and fn in {5, 6, 15, 16}:
            write_request_count += 1

            raw_bytes = p.get("raw_bytes", b"")
            reg_addr = parse_modbus_register_address(raw_bytes, fn)
            if reg_addr is not None:
                write_registers.add(reg_addr)

    unique_payloads = len(set(payloads)) if payloads else 0
    dup_payload_ratio = 0.0
    if payloads:
        dup_payload_ratio = 1.0 - (unique_payloads / len(payloads))

    packet_count = float(len(window_packets))
    write_ratio = float(write_request_count / len(window_packets)) if window_packets else 0.0

    return {
        "packet_count": packet_count,
        "bytes_total": float(sum(lengths)),
        "packet_size_mean": safe_mean(lengths),
        "packet_size_std": safe_std(lengths),
        "iat_mean": safe_mean(interarrivals),
        "iat_std": safe_std(interarrivals),
        "dup_payload_ratio": float(dup_payload_ratio),
        "write_ratio": float(write_ratio),
        "unique_write_regs": float(len(write_registers)),
    }


def features_to_vector(features: Dict[str, float]) -> np.ndarray:
    return np.array([[float(features[col]) for col in FEATURE_COLUMNS]], dtype=float)


def get_confidence_and_prediction(model: Any, feature_vector: np.ndarray) -> Tuple[str, float]:
    pred = model.predict(feature_vector)[0]
    pred_label = str(pred)

    confidence = 1.0
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(feature_vector)[0]
        confidence = float(np.max(probs))

    return pred_label, confidence


def load_model(model_path: Path) -> Any:
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    return joblib.load(model_path)


def should_skip_duplicate_prediction(
    prediction: str,
    confidence: float,
    features: Dict[str, float],
    last_event: Optional[Dict[str, Any]],
    cooldown_sec: float,
) -> bool:
    if last_event is None:
        return False

    same_prediction = last_event["prediction"] == prediction
    same_conf_bucket = abs(last_event["confidence"] - confidence) < 0.02
    same_packet_count = abs(
        last_event["features"].get("packet_count", -1) - features.get("packet_count", -2)
    ) < 1e-9
    within_cooldown = (time.time() - last_event["logged_at"]) < cooldown_sec

    return same_prediction and same_conf_bucket and same_packet_count and within_cooldown


def choose_policy_action(prediction: str) -> str:
    if prediction == "normal":
        return "forward"
    if prediction == "timing_attack":
        return "alert"
    if prediction == "replay_attack":
        return "alert"
    if prediction == "command_injection":
        return "block"
    return "alert"


def detect_primary_flow(
    window_packets: List[Dict[str, Any]],
) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    if not window_packets:
        return None, None, None, None

    first = window_packets[0]
    return (
        first.get("src_ip"),
        first.get("dst_ip"),
        first.get("src_port"),
        first.get("dst_port"),
    )


def validate_ip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def run_engine(
    interface: str,
    model_path: Path,
    window_seconds: float,
    min_packets: int,
    poll_interval: float,
    dedup_cooldown: float,
) -> None:
    model = load_model(model_path)
    buffer = PacketWindowBuffer(window_seconds=window_seconds)
    last_logged: Optional[Dict[str, Any]] = None

    print(f"[INFO] Loaded model: {model_path}")
    print(f"[INFO] Listening on interface: {interface}")
    print(f"[INFO] Window size: {window_seconds:.2f}s")
    print("[INFO] Waiting for Modbus/TCP traffic...")

    def on_packet(pkt: Any) -> None:
        nonlocal last_logged

        pkt_info = packet_to_info(pkt)
        if pkt_info is None:
            return

        buffer.add_packet(pkt_info)
        window_packets = buffer.snapshot()

        if len(window_packets) < min_packets:
            return

        features = build_features(window_packets)
        feature_vector = features_to_vector(features)

        prediction, confidence = get_confidence_and_prediction(model, feature_vector)

        if prediction not in VALID_CLASSES:
            print(f"[WARN] Model returned unexpected class: {prediction}")
            return

        if should_skip_duplicate_prediction(
            prediction=prediction,
            confidence=confidence,
            features=features,
            last_event=last_logged,
            cooldown_sec=dedup_cooldown,
        ):
            return

        src_ip, dst_ip, src_port, dst_port = detect_primary_flow(window_packets)

        event = log_event(
            prediction=prediction,
            confidence=confidence,
            features=features,
            src_ip=validate_ip_or_none(src_ip),
            dst_ip=validate_ip_or_none(dst_ip),
            src_port=src_port,
            dst_port=dst_port,
            policy_action=choose_policy_action(prediction),
            model_name=model_path.name,
            model_version="v1",
            window_seconds=window_seconds,
            protocol="modbus_tcp",
            status="new",
        )

        last_logged = {
            "prediction": prediction,
            "confidence": confidence,
            "features": features,
            "logged_at": time.time(),
        }

        print(
            f"[EVENT] pred={event['prediction']} "
            f"conf={event['confidence']:.3f} "
            f"src={event.get('src_ip')}:{event.get('src_port')} "
            f"dst={event.get('dst_ip')}:{event.get('dst_port')} "
            f"action={event['policy_action']}"
        )

    sniff(
        iface=interface,
        prn=on_packet,
        store=False,
        filter="tcp port 502",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live Modbus/TCP IDS inference engine")
    parser.add_argument(
        "--iface",
        type=str,
        default="eth0",
        help="Network interface to sniff on, e.g. eth0 or br0",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help="Path to trained sklearn/joblib model",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=0.5,
        help="Sliding window length in seconds",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=4,
        help="Minimum packets in window before predicting",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.1,
        help="Reserved for future use",
    )
    parser.add_argument(
        "--dedup-cooldown",
        type=float,
        default=1.0,
        help="Suppress near-identical repeated event logs for this many seconds",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_engine(
        interface=args.iface,
        model_path=args.model,
        window_seconds=args.window,
        min_packets=args.min_packets,
        poll_interval=args.poll_interval,
        dedup_cooldown=args.dedup_cooldown,
    )


if __name__ == "__main__":
    main()