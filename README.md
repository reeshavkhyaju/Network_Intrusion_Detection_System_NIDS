# 🛡️ Network Intrusion Detection System (NIDS)

A machine learning-based Network Intrusion Detection System using **Logistic Regression** for **binary classification** — detecting whether network traffic is **BENIGN** (normal) or an **Attack**.

## 📁 Project Structure

```
code/
├── Data_Collector.py           # Captures network traffic with labels (BENIGN / Attack)
├── Attack_Generator.py          # Generates attack traffic (portscan, tcp-flood, udp-flood)
├── Trainer.py                   # Trains Logistic Regression model
├── Attack_Detector.py           # Real-time binary attack detection
├── Data_Checker.py             # Verifies data quality
├── Quick_Start.py              # Interactive menu system
├── Complete_Workflow_Example.py # Step-by-step workflow guide
├── example_data.csv            # Example training data (BENIGN + Attack)
├── DATA_COLLECTION_GUIDE.md    # Data collection documentation
├── TRAINING_DETECTION_GUIDE.md # Training & detection documentation
└── README.md                   # This file
```

## 🚀 Quick Start

### Option 1: Interactive Menu (Easiest)

```bash
sudo python Quick_Start.py
```

### Option 2: Manual Workflow (Step by Step)

#### Step 1 — Collect BENIGN Data (10+ minutes)

```bash
# Terminal 1: Start collecting normal traffic
sudo python Data_Collector.py -l BENIGN -o training_data.csv

# Now browse the internet normally for 10+ minutes
# Press Ctrl+C to stop and save
```

#### Step 2 — Collect Attack Data (5-10 minutes)

```bash
# Terminal 1: Start collecting attack traffic
sudo python Data_Collector.py -l Attack -o training_data.csv
```

```bash
# Terminal 2: Generate attacks (run any or all of these)

# Port Scan attack
sudo python Attack_Generator.py 127.0.0.1 -a portscan --end-port 1000

# TCP Flood attack (60 seconds, 100 packets/sec)
sudo python Attack_Generator.py 127.0.0.1 -a tcp-flood -d 60 -r 100

# UDP Flood attack (60 seconds, 100 packets/sec)
sudo python Attack_Generator.py 127.0.0.1 -a udp-flood -d 60 -r 100
```

Press **Ctrl+C** on Terminal 1 when done to save data.

#### Step 3 — Check Data Quality

```bash
python Data_Checker.py training_data.csv
```

#### Step 4 — Train the Model

```bash
python Trainer.py -d training_data.csv
```

#### Step 5 — Run Real-Time Detection

```bash
# Terminal 1: Start the detector
sudo python Attack_Detector.py
```

```bash
# Terminal 2: Test with an attack
sudo python Attack_Generator.py 127.0.0.1 -a tcp-flood -d 30 -r 100
```

You should see `🚨 ATTACK DETECTED!` alerts on Terminal 1.

### Option 3: Guided Workflow

```bash
python Complete_Workflow_Example.py
```

## 📋 Prerequisites

### Required Software

**Linux (Kali/Ubuntu/Debian):**
```bash
sudo apt-get install python3 python3-pip libpcap-dev
```

**Windows:**
1. Python 3.7+
2. [Npcap](https://npcap.com/#download) (install with WinPcap compatibility mode)
3. Run PowerShell as **Administrator**

### Python Packages

```bash
pip install scapy pandas numpy scikit-learn joblib matplotlib seaborn
```

## 📊 System Components

### 1. Data Collector (`Data_Collector.py`)

Captures network packets and extracts 40+ features for binary classification.

```bash
# Collect normal traffic
sudo python Data_Collector.py -l BENIGN -o data.csv

# Collect attack traffic
sudo python Data_Collector.py -l Attack -o data.csv
```

| Option | Description |
|--------|-------------|
| `-l` | Label: `BENIGN` or `Attack` |
| `-o` | Output CSV file (appends if file exists) |
| `-t` | Flow timeout in seconds (default: 120) |
| `-i` | Network interface (default: all) |
| `-f` | BPF filter (e.g., `"tcp port 80"`) |
| `--guide` | Show attack generation guide |

---

### 2. Attack Generator (`Attack_Generator.py`)

Generates attack traffic for testing and data collection. All attacks are classified as `Attack` by the binary model.

⚠️ **WARNING: Only use on systems you own or have permission to test!**

#### Port Scan

```bash
# SYN scan (default) — ports 1 to 1000
sudo python Attack_Generator.py 192.168.1.100 -a portscan --end-port 1000

# Full connect scan
sudo python Attack_Generator.py 192.168.1.100 -a portscan --scan-type connect

# XMAS scan
sudo python Attack_Generator.py 192.168.1.100 -a portscan --scan-type xmas
```

| Option | Description |
|--------|-------------|
| `--start-port` | Start port (default: 1) |
| `--end-port` | End port (default: 1024) |
| `--scan-type` | `syn`, `connect`, `null`, `xmas` (default: syn) |

#### TCP Flood

```bash
# SYN flood for 60 seconds at 500 packets/sec
sudo python Attack_Generator.py 192.168.1.100 -a tcp-flood -p 80 -d 60 -r 500

# ACK flood at maximum speed
sudo python Attack_Generator.py 192.168.1.100 -a tcp-flood --flood-type ack -d 60 -r 0
```

| Option | Description |
|--------|-------------|
| `-p` | Target port (default: 80) |
| `-d` | Duration in seconds (default: 60) |
| `-r` | Packets/sec, 0 = max speed (default: 0) |
| `--flood-type` | `syn`, `ack`, `rst`, `fin` (default: syn) |

#### UDP Flood

```bash
# UDP flood for 60 seconds at 500 packets/sec
sudo python Attack_Generator.py 192.168.1.100 -a udp-flood -p 53 -d 60 -r 500

# Large payload flood
sudo python Attack_Generator.py 192.168.1.100 -a udp-flood --payload-size 2048 -d 60
```

| Option | Description |
|--------|-------------|
| `-p` | Target port (default: 80) |
| `-d` | Duration in seconds (default: 60) |
| `-r` | Packets/sec, 0 = max speed (default: 0) |
| `--payload-size` | UDP payload bytes (default: 1024) |

---

### 3. Model Trainer (`Trainer.py`)

Trains a **Logistic Regression** model for binary classification (BENIGN vs Attack).

```bash
# Train with default settings
python Trainer.py -d training_data.csv

# Save model to a specific directory
python Trainer.py -d training_data.csv -o models/
```

| Option | Description |
|--------|-------------|
| `-d` | Input CSV data file |
| `-a` | Algorithm: `logistic` (default) |
| `-o` | Output directory for model files (default: `.`) |
| `--no-plots` | Skip generating plot images |

**What it does:**
1. Loads CSV data
2. Remaps all non-BENIGN labels → `Attack` (binary)
3. Splits data 80/20 (train/test)
4. Scales features with StandardScaler
5. Trains Logistic Regression
6. Evaluates accuracy, precision, recall, F1
7. Saves model files

**Output Files:**

| File | Description |
|------|-------------|
| `ids_model.pkl` | Trained Logistic Regression model |
| `ids_scaler.pkl` | Feature scaler |
| `ids_labels.pkl` | Label encoder (BENIGN ↔ Attack) |
| `ids_features.pkl` | Feature names list |
| `ids_metadata.pkl` | Training metadata |
| `confusion_matrix.png` | Confusion matrix visualization |
| `feature_importance.png` | Top feature coefficients |

---

### 4. Attack Detector (`Attack_Detector.py`)

Real-time binary attack detection using the trained Logistic Regression model.

```bash
# Basic — monitor all interfaces
sudo python Attack_Detector.py

# Monitor a specific interface
sudo python Attack_Detector.py -i eth0

# Filter specific traffic
sudo python Attack_Detector.py -f "tcp port 80"

# Custom flow timeout
sudo python Attack_Detector.py -t 60

# Load model from a directory
sudo python Attack_Detector.py -m models/
```

| Option | Description |
|--------|-------------|
| `-m` | Model directory (default: `.`) |
| `-t` | Flow timeout in seconds (default: 120) |
| `-i` | Network interface (default: all) |
| `-f` | BPF filter string |

**Detection Output Example:**
```
🚨 ATTACK DETECTED!
   Source: 192.168.1.50:54321
   Destination: 192.168.1.100:80
   Protocol: 6
   Packets: 1523
   Bytes: 92380
   Confidence: 96.45%
```

All alerts are also logged to `intrusion_alerts.log`. Press **Ctrl+C** to stop.

---

### 5. Data Checker (`Data_Checker.py`)

Verifies collected data quality before training.

```bash
python Data_Checker.py training_data.csv
python Data_Checker.py --features                              # Show required features
python Data_Checker.py --merge file1.csv file2.csv -o all.csv  # Merge CSV files
```

---

## 🎯 Recommended Data Collection

| Label | Recommended Flows | Duration | How |
|-------|------------------|----------|-----|
| BENIGN | 3,000+ | 10–30 min | Browse web, stream video, normal usage |
| Attack | 3,000+ | 10–15 min | Mix of portscan, tcp-flood, udp-flood |

**Tips:**
- Balance the dataset (roughly equal BENIGN and Attack)
- Use different attack intensities and targets for variety
- Collect BENIGN traffic at different times of day

## 📈 Expected Performance

| Metric | Expected |
|--------|----------|
| Overall Accuracy | 90–99% |
| F1-Score (both classes) | > 0.85 |
| False Positive Rate | < 5% |
| Training Time | 5–60 seconds |
| Detection Speed | < 100ms per flow |
| Throughput | 100–1000 packets/sec |

**Example Output:**
```
📊 MODEL EVALUATION
────────────────────────────────────────────
✅ Overall Accuracy: 97.85%

📋 Per-Class Performance:
Class            Precision    Recall      F1-Score
────────────────────────────────────────────
Attack          0.9812       0.9756      0.9784
BENIGN          0.9856       0.9921      0.9888
────────────────────────────────────────────
WEIGHTED AVG    0.9834       0.9838      0.9836
```

## 🔧 Configuration

### Data Collector
```python
flow_timeout = 120     # seconds
label = "BENIGN"       # BENIGN or Attack
```

### Trainer
```python
test_size = 0.2        # 80/20 train/test split
algorithm = "logistic" # Logistic Regression
max_iter = 1000        # Max iterations
```

### Detector
```python
flow_timeout = 120     # seconds
alert_log = "intrusion_alerts.log"
```

## 🐛 Troubleshooting

### Data Collection

| Problem | Solution |
|---------|----------|
| "Permission denied" | Run with `sudo` (Linux) or as Administrator (Windows) |
| "No packets captured" | Check interface: `python -c "from scapy.all import show_interfaces; show_interfaces()"` |
| "Npcap not found" (Windows) | Install from https://npcap.com with WinPcap compatibility, reboot |

### Training

| Problem | Solution |
|---------|----------|
| "Label column not found" | Verify CSV has `Label` column — run `python Data_Checker.py your_data.csv` |
| Low accuracy (< 85%) | Collect more data, ensure good balance between BENIGN and Attack |
| Memory error | Reduce dataset size or subsample |

### Detection

| Problem | Solution |
|---------|----------|
| "Model file not found" | Train first: `python Trainer.py -d training_data.csv` |
| No alerts appearing | Test with a known attack from another terminal |
| Too many false positives | Collect more diverse benign data and retrain |

## 🔒 Security & Ethics

⚠️ **IMPORTANT LEGAL NOTICE**

This tool is for:
- ✅ Educational purposes
- ✅ Testing your own systems
- ✅ Authorized security assessments
- ✅ Network research with permission

**NEVER:**
- ❌ Attack systems without authorization
- ❌ Use in production without proper testing
- ❌ Conduct unauthorized security testing

Unauthorized network attacks are **illegal** and can result in criminal charges.

## 🎉 Quick Success Path

1. Install packages: `pip install scapy pandas numpy scikit-learn joblib matplotlib seaborn`
2. Collect BENIGN: `sudo python Data_Collector.py -l BENIGN -o data.csv` (browse for 10 min)
3. Collect Attack: `sudo python Data_Collector.py -l Attack -o data.csv` + run attacks from Terminal 2
4. Check quality: `python Data_Checker.py data.csv`
5. Train model: `python Trainer.py -d data.csv`
6. Start detector: `sudo python Attack_Detector.py`
7. Test: `sudo python Attack_Generator.py 127.0.0.1 -a tcp-flood -d 30 -r 100`
8. 🎉 **You now have a working IDS!**

## 📚 Documentation

- **[DATA_COLLECTION_GUIDE.md](DATA_COLLECTION_GUIDE.md)** — Data collection guide
- **[TRAINING_DETECTION_GUIDE.md](TRAINING_DETECTION_GUIDE.md)** — Training & detection guide
- **Complete_Workflow_Example.py** — Interactive step-by-step walkthrough
- **Quick_Start.py** — Menu-driven interface

---

**Made with ❤️ for network security**

🛡️ Stay safe and secure!
