# Network Intrusion Detection System - Data Collection Guide

## Overview

This guide will help you collect your own network traffic data for training an IDS model. The collected data will be in the same format as CICIDS2017 dataset.

## Files

1. **Data_Collector.py** - Captures network traffic and extracts features
2. **Attack_Generator.py** - Generates various network attacks
3. **Trainer.py** - Trains the ML model
4. **Real_Time_Sniffer.py** - Real-time intrusion detection

## Prerequisites

### Required Python Packages

```bash
pip install scapy pandas numpy scikit-learn joblib
```

### Windows-Specific Requirements

1. **Install Npcap** (required for Scapy on Windows):
   - Download from: https://npcap.com/#download
   - Install with WinPcap compatibility mode enabled

2. **Run as Administrator**:
   - Both scripts require administrator privileges to capture packets

### Linux Requirements

```bash
sudo apt-get install python3-scapy
```

## Data Collection Workflow

### Step 1: Set Up Test Environment

You need two machines (or VMs) on the same network:
- **Machine A**: Run Data_Collector.py (captures traffic)
- **Machine B**: Run Attack_Generator.py (generates attacks)

Alternatively, use one machine with localhost (127.0.0.1) for testing.

### Step 2: Collect BENIGN Traffic

First, collect normal traffic data:

```bash
# Run as Administrator/sudo
python Data_Collector.py -l BENIGN -o training_data.csv -t 60
```

While this is running:
- Browse websites
- Download files
- Use normal applications
- Stream videos

Let it run for 5-10 minutes, then press Ctrl+C to stop.

### Step 3: Collect Port Scan Data

#### On Machine A (Collector):
```bash
python Data_Collector.py -l PortScan -o training_data.csv -t 60
```

#### On Machine B (Attacker):
```bash
# Replace <TARGET_IP> with Machine A's IP
python Attack_Generator.py <TARGET_IP> -a portscan --start-port 1 --end-port 5000
```

Let it complete the scan, then stop the collector with Ctrl+C.

### Step 4: Collect DoS TCP Data

#### On Machine A (Collector):
```bash
python Data_Collector.py -l DoS-TCP -o training_data.csv -t 60
```

#### On Machine B (Attacker):
```bash
# SYN Flood attack
python Attack_Generator.py <TARGET_IP> -a dos-tcp -p 80 -d 180 -r 500 --flood-type syn
```

Run for 2-3 minutes, then stop both.

### Step 5: Collect DoS UDP Data

#### On Machine A (Collector):
```bash
python Data_Collector.py -l DoS-UDP -o training_data.csv -t 60
```

#### On Machine B (Attacker):
```bash
# UDP Flood attack
python Attack_Generator.py <TARGET_IP> -a dos-udp -p 53 -d 180 -r 500 --payload-size 512
```

Run for 2-3 minutes, then stop both.

## Command Reference

### Data_Collector.py Options

```
-l, --label         Traffic label (BENIGN, PortScan, DoS-TCP, DoS-UDP)
-o, --output        Output CSV file (default: collected_data.csv)
-t, --timeout       Flow timeout in seconds (default: 120)
-i, --interface     Network interface to capture on
-f, --filter        BPF filter (e.g., "tcp port 80")
--guide             Show attack generation guide
```

### Examples:

```bash
# Collect benign traffic
python Data_Collector.py -l BENIGN -o my_data.csv

# Collect only TCP traffic on port 80
python Data_Collector.py -l DoS-TCP -f "tcp port 80"

# Collect on specific interface with short timeout
python Data_Collector.py -l PortScan -i eth0 -t 30

# Show attack guide
python Data_Collector.py --guide
```

### Attack_Generator.py Options

```
target_ip           Target IP address (required)
-p, --port          Target port (default: 80)
-a, --attack        Attack type: portscan, dos-tcp, dos-udp (required)
-d, --duration      Attack duration in seconds (default: 60)
-r, --rate          Packets per second (0 = flood mode)
--start-port        Port scan start (default: 1)
--end-port          Port scan end (default: 1024)
--scan-type         Scan type: syn, connect, null, xmas
--flood-type        TCP flood: syn, ack, rst, fin
--payload-size      UDP payload size in bytes (default: 1024)
```

### Examples:

```bash
# Port Scan - SYN scan
python Attack_Generator.py 192.168.1.100 -a portscan --start-port 1 --end-port 1000

# Port Scan - Full connect scan
python Attack_Generator.py 192.168.1.100 -a portscan --scan-type connect

# DoS TCP - SYN Flood (500 packets/sec)
python Attack_Generator.py 192.168.1.100 -a dos-tcp -p 80 -d 120 -r 500

# DoS TCP - Maximum speed flood
python Attack_Generator.py 192.168.1.100 -a dos-tcp -p 80 -d 120 -r 0

# DoS UDP - Slow flood
python Attack_Generator.py 192.168.1.100 -a dos-udp -p 53 -d 120 -r 100

# DoS UDP - Large payloads
python Attack_Generator.py 192.168.1.100 -a dos-udp -p 53 --payload-size 2048
```

## Recommended Data Collection Strategy

For a balanced dataset:

| Attack Type | Recommended Flows | Duration | Variety |
|-------------|------------------|----------|---------|
| BENIGN      | 10,000+          | 30-60 min| Different activities |
| PortScan    | 5,000+           | 10-15 min| Different scan types |
| DoS-TCP     | 5,000+           | 10-15 min| Different rates/flags |
| DoS-UDP     | 5,000+           | 10-15 min| Different payloads |

### Tips for Good Data Quality:

1. **Variety**: Run each attack type multiple times with different parameters
2. **Balance**: Collect roughly equal amounts of each attack type
3. **Realism**: Mix slow and fast attacks, different ports, different targets
4. **Benign Data**: Collect during actual usage, not idle time
5. **Validation**: Check the CSV file to ensure all labels are present

## Training the Model

After collecting data:

```bash
# Check collected data
python -c "import pandas as pd; df = pd.read_csv('training_data.csv'); print(df['Label'].value_counts())"

# Train model
python Trainer.py
```

Update Trainer.py to use your collected data:

```python
df = pd.read_csv('training_data.csv')
```

## Testing the Model

After training:

```bash
python Real_Time_Sniffer.py
```

Generate attacks from another machine to test detection.

## Troubleshooting

### "Permission denied" Error
- Windows: Run PowerShell as Administrator
- Linux: Use `sudo python3 Data_Collector.py ...`

### "No module named 'scapy'"
```bash
pip install scapy
```

### Npcap Issues (Windows)
1. Uninstall existing WinPcap/Npcap
2. Download latest Npcap from https://npcap.com
3. Install with "WinPcap compatibility mode" checked
4. Reboot

### No Packets Captured
1. Check if you're using the correct network interface:
   ```bash
   # List interfaces (Windows)
   python -c "from scapy.all import *; show_interfaces()"
   
   # Then specify the interface
   python Data_Collector.py -l BENIGN -i "Ethernet"
   ```

2. Check firewall settings
3. Ensure network traffic is actually flowing

### Attack Generator Not Working
- Ensure both machines can ping each other
- Check firewall rules
- Try with localhost (127.0.0.1) first
- Verify admin/sudo privileges

## Features Extracted

The collector extracts these features (compatible with CICIDS2017):

- Flow Duration
- Total Fwd/Bwd Packets
- Total Length of Fwd/Bwd Packets
- Fwd/Bwd Packet Length Max/Min/Mean
- Flow Bytes/s and Packets/s
- Flow IAT Mean, Fwd/Bwd IAT Mean
- TCP Flags (FIN, SYN, RST, PSH, ACK, URG)
- Down/Up Ratio
- Average Packet Size
- Fwd/Bwd Segment Size Avg
- Subflow metrics
- Initial Window Bytes
- Label

## Ethical Considerations

⚠️ **IMPORTANT**: 

1. **Only test on systems you own or have explicit permission to test**
2. **Never use these tools on production systems without approval**
3. **Be aware that generating attacks may trigger security alerts**
4. **Some attacks may cause service degradation or crashes**
5. **Unauthorized testing is illegal in most jurisdictions**

## Next Steps

1. Collect diverse samples of each attack type
2. Verify data quality and balance
3. Train the model with your collected data
4. Test detection accuracy
5. Fine-tune by collecting more specific attack patterns that are misclassified

## Example Complete Workflow

```bash
# Terminal 1 (Collector Machine)
python Data_Collector.py -l BENIGN -o my_ids_data.csv
# Browse internet for 10 minutes, then Ctrl+C

python Data_Collector.py -l PortScan -o my_ids_data.csv
# Terminal 2 (Attacker Machine)
python Attack_Generator.py 192.168.1.100 -a portscan --end-port 5000
# Wait for completion, Ctrl+C on collector

# Repeat for DoS-TCP
python Data_Collector.py -l DoS-TCP -o my_ids_data.csv
python Attack_Generator.py 192.168.1.100 -a dos-tcp -d 180 -r 500

# Repeat for DoS-UDP
python Data_Collector.py -l DoS-UDP -o my_ids_data.csv
python Attack_Generator.py 192.168.1.100 -a dos-udp -d 180 -r 500

# Train model
python Trainer.py  # (update to use my_ids_data.csv)

# Test in real-time
python Real_Time_Sniffer.py
```

## Support

If you encounter issues:
1. Check that all packages are installed
2. Verify admin/sudo privileges
3. Test with localhost first
4. Check the log messages for specific errors
5. Ensure Npcap/libpcap is properly installed

Good luck with your IDS development!
