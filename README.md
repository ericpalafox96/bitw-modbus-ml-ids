# Senior Project — BITW Modbus/TCP IDS (Jetson Orin Nano)
> ⚡ Real-time ML-based intrusion detection system for industrial Modbus/TCP traffic deployed inline using a Jetson Orin Nano.

A bump-in-the-wire (BITW) intrusion detection system for Modbus/TCP traffic.

This system runs inline on a **Jetson Orin Nano** configured as a transparent Layer-2 bridge between:

- Laptop A (Controller / Attacker)
- Laptop B (DER / Modbus Server)

The Jetson extracts 0.5-second windowed traffic features and classifies activity using a lightweight Random Forest model.

---
## Project Overview

The goal of this project is to design and deploy an inline ML-based intrusion detection system capable of detecting:

- Normal Modbus traffic
- Timing attacks
- Replay attacks
- Command injection attacks

All traffic must pass through the Jetson BITW device before reaching the DER.

---
## ⚡ Live System Demo (End-to-End)

The system has been validated with a full real-time pipeline:

    Modbus Traffic → Feature Extraction → ML Inference → Event Logging → Dashboard

- Replay attacks are detected in real-time  
- Events are logged to `ids_events.jsonl`  
- Dashboard updates live with:
  - predictions
  - confidence scores
  - source/destination IPs
  - recommended actions  

### Example Detection Output

- Class: `replay_attack`  
- Severity: `high`  
- Confidence: ~0.6–0.8  
- Flow: `192.168.50.10 → 192.168.50.20:502`  

### Observed Behavior

- Attack rate reached 100% during replay attack testing  
- Top class correctly identified as `replay_attack`  
- Continuous real-time detection stream observed  

---
## 🖥️ Local Execution (Laptop A)

### 1️⃣ Start Dashboard

    set PYTHONPATH=src && python -m uvicorn runtime.dashboard.app:app --reload

Open in browser:

    http://127.0.0.1:8000

---

### 2️⃣ Start Inference Engine

    set PYTHONPATH=src && python -m runtime.inference_engine --iface Ethernet --model data\models\rf_4class.pkl

---

### 3️⃣ Generate Traffic

Normal traffic:

    python src/controller_client.py

Replay attack:

    python src/modbus_replay.py

---

### Expected Behavior

- Dashboard updates in real-time  
- Events appear in table and charts  
- Attack types are classified correctly  
- Replay attack events show:
  - high severity  
  - alert action  

---

## 🧠 Feature Set (Model Input)

The model uses the following features:

- packet_count  
- bytes_total  
- packet_size_mean  
- packet_size_std  
- iat_mean  
- iat_std  
- dup_payload_ratio  
- write_ratio  
- unique_write_regs  

These features are extracted from 0.5-second sliding windows of Modbus traffic.

---

## 🧪 Detection Pipeline

1. Capture packets (Scapy)  
2. Aggregate into 0.5-second windows  
3. Extract features  
4. Run Random Forest model  
5. Log event  
6. Dashboard consumes logs in real-time  

---

## 🚨 Detection Classes

| Class               | Description |
|--------------------|------------|
| normal             | Baseline Modbus behavior |
| timing_attack      | Abnormal polling frequency |
| replay_attack      | Repeated identical requests |
| command_injection  | Unauthorized control commands |

---
## High-Level Architecture
```
Laptop A (Controller / Attacker)
|
Ethernet
|
Jetson Orin Nano (br0 bridge)
|
Ethernet
|
Laptop B (DER / PLC Simulator)
```
The Jetson performs:

- Transparent packet forwarding
- Window-based feature extraction (0.5s)
- Real-time ML classification
- Logging and alerting

---
## Repository Structure
```
src/
├── features/ # PCAP → feature extraction and window sweep
├── training/ # Model training, evaluation, feature importance
└── runtime/ # Real-time IDS script for Jetson (br0)

data/
├── pcaps/ # Local-only PCAP captures (ignored by Git)
├── features/ # Generated feature CSV files
└── models/ # Saved trained models (.pkl)

docs/
└── diagrams/ # Architecture and report diagrams
```

Notes:
- PCAP files are intentionally excluded from GitHub due to size limits.
- Feature CSV files are tracked for reproducibility.
- The trained model can be regenerated using the training scripts.

---
## Environment Setup

### Development Environment (Windows)

Recommended:
- Python 3.9+
- Anaconda environment (`der_ml_env`)

Create and activate environment:

```bash
conda create -n der_ml_env python=3.9
conda activate der_ml_env
pip install -r requirements.txt
```

---
## Jetson Runtime Environment

On Jetson Orin Nano:
- Ubuntu (JetPack)
- Python 3.x
- Linux bridge configured as br0

Install required packages:
```
sudo apt update
sudo apt install python3-pip
pip3 install -r requirements.txt
```

Required Python Libraries:
- numpy
- pandas
- scikit-learn
- scapy
- pymodbus
- matplotlib

---
## Feature Extraction & Training Workflow

### 1️⃣ Capture Modbus Traffic

Using Wireshark, capture traffic for each scenario and save locally:

- `normal.pcapng`
- `timing_attack.pcapng`
- `replay_attack.pcapng`
- `command_injection.pcapng`

Place PCAP files in:
```
data/pcaps/
```
---
### 2️⃣ Convert PCAP to Feature Windows

Example (0.5-second window):

```bash
python src/features/pcap_to_features.py \
  --pcap data/pcaps/normal.pcapng \
  --window 0.5 \
  --label normal \
  --out data/features/features_normal.csv
```
Note: Repeat for each attack type.

---
### 3️⃣ Window Size Sensitivity Analysis

To evaluate detection accuracy vs. latency:
```bash
python src/features/window_sweep.py
```
This tests multiple window sizes and selects the optimal value.

Final selected window size: 0.5 seconds

---
## 4️⃣ Train Multi-Class Model

```bash
python src/training/train_multiclass.py
```

Outputs:
- Confusion matrix
- Classification report
- Feature importance ranking
- Saved model (data/models/rf_4class.pkl)

---

## Jetson Runtime & Deployment

### Inline BITW Configuration

The Jetson Orin Nano operates as a transparent Layer-2 bridge (`br0`) between the controller and DER devices.

Verification steps:

```bash
# Confirm connectivity across bridge
ping <DER_IP>

# Confirm Modbus works
python controller_client.py

# Confirm traffic visibility on Jetson
sudo tcpdump -i br0 port 502
```
All traffic must pass through br0

---
## Real-Time IDS Operation

The runtime phase performs:
1. Live packet sniffing on br0
2. 0.5-second sliding window aggregation
3. Feature extraction (same features used in training)
4. Model inference using rf_4class.pkl
5. Logging predicted class

Detection classes:
- normal
- timing_attack
- replay_attack
- command_injection

| Detected Class    | Enforcement Policy                                      |
| ----------------- | ------------------------------------------------------- |
| Normal            | Transparent forwarding                                  |
| Timing Attack     | Log event + alert                                       |
| Replay Attack     | Log event + terminate suspicious session (policy-based) |
| Command Injection | Drop packet + require re-authentication                 |

The system is designed to operate in fail-open mode to preserve availability in industrial environments.

Notes:
- Wi-Fi should be disabled during BITW testing to prevent routing around the bridge.
- PCAP files are excluded from version control due to GitHub size limits.
- The trained model can be regenerated at any time using the training scripts.

---