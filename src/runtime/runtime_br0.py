import time
import joblib
import numpy as np
from scapy.all import sniff, TCP, IP, Raw

# ====== CONFIG ======
IFACE = "br0"
MODEL_PATH = "rf_4class.pkl"
WINDOW_SECONDS = 0.5
MIN_PKTS_PER_WINDOW = 3
PORT = 502

# ====== STATE ======
packet_buffer = []

model = joblib.load(MODEL_PATH)


def reset_window():
    global packet_buffer
    packet_buffer = []


def compute_features(packets):
    if len(packets) == 0:
        return None

    packet_count = len(packets)
    sizes = [len(p) for p in packets]
    bytes_total = sum(sizes)

    packet_size_mean = np.mean(sizes)
    packet_size_std = np.std(sizes)

    times = [p.time for p in packets]
    if len(times) > 1:
        iats = np.diff(times)
        iat_mean = np.mean(iats)
        iat_std = np.std(iats)
    else:
        iat_mean = 0
        iat_std = 0

    payloads = []
    for p in packets:
        if Raw in p:
            payloads.append(bytes(p[Raw].load))
        else:
            payloads.append(b"")

    unique_payloads = len(set(payloads))
    dup_payload_ratio = 1 - (unique_payloads / len(payloads)) if payloads else 0

    write_count = 0
    write_regs = set()

    for p in packets:
        if TCP in p and Raw in p:
            payload = bytes(p[Raw].load)

            if len(payload) > 7:
                func_code = payload[7]

                if func_code in [5, 6, 15, 16]:
                    write_count += 1

                    if len(payload) > 9:
                        reg = payload[8:10]
                        write_regs.add(reg)

    write_ratio = write_count / packet_count if packet_count > 0 else 0
    unique_write_regs = len(write_regs)

    return np.array([[
        packet_count,
        bytes_total,
        packet_size_mean,
        packet_size_std,
        iat_mean,
        iat_std,
        dup_payload_ratio,
        write_ratio,
        unique_write_regs
    ]])


def predict_and_print():
    global packet_buffer

    if len(packet_buffer) < MIN_PKTS_PER_WINDOW:
        reset_window()
        return

    feats = compute_features(packet_buffer)
    if feats is None:
        reset_window()
        return

    pred = model.predict(feats)[0]
    print(f"[{time.strftime('%H:%M:%S')}] pkts={len(packet_buffer)} pred={pred}")

    reset_window()


def handle_pkt(pkt):
    global packet_buffer

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    tcp = pkt[TCP]
    if tcp.sport != PORT and tcp.dport != PORT:
        return

    packet_buffer.append(pkt)


if __name__ == "__main__":
    print(f"Loaded model: {MODEL_PATH}")
    print(f"Sniffing on {IFACE} for TCP/{PORT} ...")

    while True:
        sniff(iface=IFACE, prn=handle_pkt, store=False, timeout=WINDOW_SECONDS)
        predict_and_print()