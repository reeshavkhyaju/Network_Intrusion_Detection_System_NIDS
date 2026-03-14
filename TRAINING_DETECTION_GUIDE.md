# 🎓 Model Training & Attack Detection Guide

## Complete Workflow for Network Intrusion Detection

This guide covers training the ML model and using it for real-time attack detection.

---

## 📋 Prerequisites

Before starting, ensure you have:

1. ✅ Collected training data using `Data_Collector.py`
2. ✅ Data file (e.g., `collected_data.csv`) with labeled traffic
3. ✅ All required Python packages installed:
   ```bash
   pip install scapy pandas numpy scikit-learn joblib matplotlib seaborn
   ```
4. ✅ Administrator/sudo privileges for packet capture

---

## 🎯 Part 1: Training the Model

### Basic Training

Train with default settings (Random Forest):

```bash
python Trainer.py -d collected_data.csv
```

This will:
- Load and preprocess the data
- Train a Random Forest classifier
- Evaluate performance
- Save model files: `ids_model.pkl`, `ids_scaler.pkl`, `ids_labels.pkl`

### Advanced Training Options

**Try different algorithms:**

```bash
# Random Forest (best for accuracy)
python Trainer.py -d collected_data.csv -a random_forest

# Gradient Boosting (good balance)
python Trainer.py -d collected_data.csv -a gradient_boosting

# Decision Tree (fastest)
python Trainer.py -d collected_data.csv -a decision_tree

# Logistic Regression (good for binary classification)
python Trainer.py -d collected_data.csv -a logistic

# SVM (high accuracy but slower)
python Trainer.py -d collected_data.csv -a svm
```

**Optimize hyperparameters (slower but better):**

```bash
python Trainer.py -d collected_data.csv --optimize
```

**Save to specific directory:**

```bash
python Trainer.py -d collected_data.csv -o models/
```

### Understanding the Output

After training, you'll see:

```
📊 MODEL EVALUATION
─────────────────────────────────────────────
✅ Overall Accuracy: 98.45%

📋 Per-Class Performance:
Class                Precision    Recall      F1-Score
─────────────────────────────────────────────
BENIGN              0.9921       0.9956      0.9938
PortScan            0.9845       0.9823      0.9834
DoS-TCP             0.9789       0.9801      0.9795
DoS-UDP             0.9812       0.9788      0.9800
```

**Key Metrics:**
- **Precision**: % of detected attacks that are real attacks (low false positives)
- **Recall**: % of real attacks that are detected (low false negatives)
- **F1-Score**: Balance between precision and recall

**Good Performance:**
- Overall Accuracy: > 95%
- All F1-Scores: > 0.90
- Balanced confusion matrix

### Generated Files

After training, you'll have:

| File | Description |
|------|-------------|
| `ids_model.pkl` | Trained ML model |
| `ids_scaler.pkl` | Feature scaler |
| `ids_labels.pkl` | Label encoder |
| `ids_features.pkl` | Feature names |
| `ids_metadata.pkl` | Training metadata |
| `confusion_matrix.png` | Visual confusion matrix |
| `feature_importance.png` | Most important features |

---

## 🚨 Part 2: Real-Time Attack Detection

### Basic Detection

Start monitoring all network traffic:

```bash
# Run as Administrator/sudo
python Attack_Detector.py
```

### Advanced Detection Options

**Monitor specific interface:**

```bash
# Windows
python Attack_Detector.py -i "Ethernet"

# Linux
python Attack_Detector.py -i eth0
```

**Filter specific traffic:**

```bash
# Only TCP traffic
python Attack_Detector.py -f "tcp"

# Only port 80
python Attack_Detector.py -f "port 80"

# HTTP/HTTPS traffic
python Attack_Detector.py -f "tcp port 80 or tcp port 443"

# Specific IP address
python Attack_Detector.py -f "host 192.168.1.100"
```

**Custom flow timeout:**

```bash
# 60 second timeout (faster detection, less accurate)
python Attack_Detector.py -t 60

# 300 second timeout (slower detection, more accurate)
python Attack_Detector.py -t 300
```

**Load model from different directory:**

```bash
python Attack_Detector.py -m models/
```

### Understanding Detection Output

**Normal Traffic (Green):**
```
✓ Normal traffic: 192.168.1.100:52341 -> 93.184.216.34:443
```

**Attack Detected (Red):**
```
🚨 ATTACK DETECTED: DoS-TCP
   Source: 192.168.1.50:54321
   Destination: 192.168.1.100:80
   Protocol: 6
   Packets: 1523
   Bytes: 92380
   Confidence: 96.45%
```

### Alert Logging

All alerts are automatically logged to `intrusion_alerts.log`:

```
2026-02-14 15:30:45 - WARNING - ATTACK: PortScan | 192.168.1.50:0 -> 192.168.1.100:0
2026-02-14 15:31:12 - WARNING - ATTACK: DoS-TCP | 192.168.1.50:54321 -> 192.168.1.100:80
```

---

## 🔄 Complete Example Workflow

### Step 1: Collect Training Data

```bash
# Terminal 1: Collect normal traffic
python Data_Collector.py -l BENIGN -o training_data.csv
# Browse internet for 10 minutes, Ctrl+C

# Terminal 1: Collect port scan traffic
python Data_Collector.py -l PortScan -o training_data.csv

# Terminal 2: Generate port scan
python Attack_Generator.py 127.0.0.1 -a portscan --end-port 5000

# Repeat for DoS-TCP and DoS-UDP...
```

### Step 2: Verify Data Quality

```bash
python Data_Checker.py training_data.csv
```

Example output:
```
📊 LABEL DISTRIBUTION
───────────────────────────────────────────
Label                Count           Percentage       Status
───────────────────────────────────────────
BENIGN               12,543          45.25%        ✓✓ Excellent
PortScan             5,231           18.87%        ✓ Good
DoS-TCP              5,104           18.41%        ✓ Good
DoS-UDP              4,847           17.47%        ✓ Good
```

### Step 3: Train the Model

```bash
python Trainer.py -d training_data.csv -a random_forest
```

Wait for training to complete (~2-5 minutes depending on data size).

### Step 4: Test Detection

```bash
# Terminal 1: Start detector
python Attack_Detector.py

# Terminal 2: Generate test attack
python Attack_Generator.py 127.0.0.1 -a dos-tcp -d 30 -r 100
```

Watch Terminal 1 for attack alerts! 🚨

---

## 📊 Improving Model Performance

### If Accuracy is Low (< 90%)

1. **Collect More Data**
   - Aim for 10,000+ samples per attack type
   - Ensure balanced dataset

2. **Try Different Algorithms**
   ```bash
   python Trainer.py -d training_data.csv -a gradient_boosting
   ```

3. **Optimize Hyperparameters**
   ```bash
   python Trainer.py -d training_data.csv --optimize
   ```

4. **Check Data Quality**
   ```bash
   python Data_Checker.py training_data.csv
   ```

### If False Positives are High

- Collect more diverse BENIGN traffic
- Increase flow timeout: `python Attack_Detector.py -t 300`
- Use stricter algorithm: `python Trainer.py -d training_data.csv -a gradient_boosting`

### If False Negatives are High

- Collect more varied attack samples
- Reduce flow timeout: `python Attack_Detector.py -t 60`
- Ensure attacks in training data match real attacks

---

## 🎯 Testing Your IDS

### Test Scenarios

**1. Port Scan Detection:**
```bash
# Terminal 1
python Attack_Detector.py

# Terminal 2
python Attack_Generator.py 127.0.0.1 -a portscan --end-port 1000
```

**2. DoS TCP Detection:**
```bash
# Terminal 1
python Attack_Detector.py

# Terminal 2
python Attack_Generator.py 127.0.0.1 -a dos-tcp -d 60 -r 500
```

**3. DoS UDP Detection:**
```bash
# Terminal 1
python Attack_Detector.py

# Terminal 2
python Attack_Generator.py 127.0.0.1 -a dos-udp -d 60 -r 500
```

**4. Normal Traffic (Should NOT Alert):**
```bash
# Start detector
python Attack_Detector.py

# Browse websites normally - should show green "Normal traffic" messages
```

---

## 🔍 Troubleshooting

### Training Issues

**"File not found" error:**
- Ensure you have collected data first
- Check file path: `python Trainer.py -d path/to/your/data.csv`

**"Label column not found":**
- Data file must have a 'Label' column
- Verify with: `python Data_Checker.py your_data.csv`

**Memory error:**
- Reduce data size or use smaller algorithm
- Try Decision Tree: `python Trainer.py -d data.csv -a decision_tree`

**Low accuracy:**
- Need more training data (10,000+ samples per class)
- Check data balance with: `python Data_Checker.py data.csv`
- Try different algorithm or optimize

### Detection Issues

**"Model file not found":**
- Train model first: `python Trainer.py -d collected_data.csv`
- Check current directory has `ids_model.pkl`

**No packets captured:**
- Run as Administrator/sudo
- Check network interface: `python Attack_Detector.py -i "Ethernet"`
- Verify Npcap installed (Windows)

**No alerts showing:**
- Model might be working correctly (no attacks present)
- Test with: `python Attack_Generator.py 127.0.0.1 -a portscan`
- Check `intrusion_alerts.log` for logged alerts

**Too many false positives:**
- Increase flow timeout: `python Attack_Detector.py -t 300`
- Retrain with more diverse benign data
- Try different algorithm

---

## 📈 Performance Metrics

### Expected Performance

**Good Model:**
- Training Accuracy: > 95%
- Test Accuracy: > 93%
- All F1-Scores: > 0.90
- Training Time: 2-10 minutes

**Detection Performance:**
- Port Scan: ~95-99% detection rate
- DoS TCP: ~93-98% detection rate
- DoS UDP: ~93-97% detection rate
- False Positive Rate: < 5%

**Real-Time Performance:**
- Can analyze 100-1000 packets/second
- Flow processing: < 100ms
- Memory usage: 100-500 MB

---

## 🚀 Production Deployment

For production use:

1. **Train with Large Dataset** (50,000+ samples)
2. **Validate Thoroughly** (test all attack scenarios)
3. **Monitor Performance** (track false positives/negatives)
4. **Update Regularly** (retrain with new attack patterns)
5. **Set Up Alerts** (integrate with SIEM/monitoring system)

### Integration Example

```python
# Custom alert handler
import smtplib

def send_email_alert(attack_type, source_ip):
    # Send email notification
    pass

# Modify Attack_Detector.py to call send_email_alert()
```

---

## 📚 Command Reference

### Training Commands

```bash
# Basic training
python Trainer.py -d collected_data.csv

# Different algorithms
python Trainer.py -d data.csv -a random_forest
python Trainer.py -d data.csv -a gradient_boosting
python Trainer.py -d data.csv -a decision_tree

# With optimization
python Trainer.py -d data.csv --optimize

# Save to directory
python Trainer.py -d data.csv -o models/

# Skip plots (faster)
python Trainer.py -d data.csv --no-plots
```

### Detection Commands

```bash
# Basic detection
python Attack_Detector.py

# Specific interface
python Attack_Detector.py -i eth0

# With filter
python Attack_Detector.py -f "tcp port 80"

# Custom timeout
python Attack_Detector.py -t 60

# Load model from directory
python Attack_Detector.py -m models/

# Combined options
python Attack_Detector.py -i eth0 -t 120 -f "tcp"
```

---

## 🎉 Success Checklist

- [✓] Collected balanced training data (all attack types)
- [✓] Verified data quality with Data_Checker.py
- [✓] Trained model with > 95% accuracy
- [✓] Generated confusion matrix and feature importance plots
- [✓] Tested detection with all attack types
- [✓] Verified low false positive rate
- [✓] Integrated alert logging
- [✓] Ready for production deployment!

---

## 📞 Need Help?

1. Check data quality: `python Data_Checker.py your_data.csv`
2. Review training output for accuracy metrics
3. Test with simple attacks first
4. Ensure running as Administrator/sudo
5. Verify all model files exist (ids_model.pkl, etc.)

For best results:
- Use Random Forest algorithm (best accuracy)
- Collect 10,000+ samples per attack type
- Test detection thoroughly before production use

Good luck with your Network Intrusion Detection System! 🛡️
