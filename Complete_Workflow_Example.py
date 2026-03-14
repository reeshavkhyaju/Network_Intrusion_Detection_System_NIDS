#!/usr/bin/python3
"""
Complete IDS Workflow Example
Demonstrates the entire process from data collection to detection
Binary classification: BENIGN vs Attack using Logistic Regression
"""

import os
import sys
import time

def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")

def print_step(number, title):
    print(f"\n{'─'*70}")
    print(f"STEP {number}: {title}")
    print('─'*70)

def pause(message="Press Enter to continue..."):
    input(f"\n{message}")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║      NETWORK INTRUSION DETECTION SYSTEM (IDS)                ║
    ║      Binary Classification: BENIGN vs Attack                 ║
    ║      Model: Logistic Regression                              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    
    This script demonstrates the complete workflow:
    1. Data Collection (BENIGN + Attack)
    2. Data Quality Check
    3. Model Training (Logistic Regression)
    4. Real-Time Detection
    
    """)
    
    pause("Press Enter to start...")
    
    # ============================================================
    # STEP 1: Data Collection
    # ============================================================
    print_step(1, "DATA COLLECTION")
    
    print("""
    First, we need to collect network traffic data with labels.
    We use two labels: BENIGN (normal) and Attack.
    
    You need TWO terminals:
    
    Terminal 1 (Data Collector - BENIGN traffic):
    ──────────────────────────────────────────────
    python Data_Collector.py -l BENIGN -o example_data.csv
    # Browse internet normally for 10+ minutes
    # Press Ctrl+C to save
    
    Terminal 1 (Data Collector - Attack traffic):
    ─────────────────────────────────────────────
    python Data_Collector.py -l Attack -o example_data.csv
    # Switch to Terminal 2 and run attacks...
    
    Terminal 2 (Attack Generator):
    ──────────────────────────────
    # Port scan attack
    python Attack_Generator.py 127.0.0.1 -a portscan --end-port 1000
    
    # TCP flood attack
    python Attack_Generator.py 127.0.0.1 -a tcp-flood -d 120 -r 100
    
    # UDP flood attack
    python Attack_Generator.py 127.0.0.1 -a udp-flood -d 120 -r 100
    
    MINIMUM RECOMMENDED:
    - BENIGN: 3,000+ flows (10+ minutes of normal browsing)
    - Attack: 3,000+ flows (mix of portscan, tcp-flood, udp-flood)
    """)
    
    pause()
    
    # ============================================================
    # STEP 2: Data Quality Check
    # ============================================================
    print_step(2, "DATA QUALITY CHECK")
    
    print("""
    After collecting data, verify its quality:
    
    Command:
    ────────
    python Data_Checker.py example_data.csv
    
    What to look for:
    ─────────────────
    ✓ Both labels present (BENIGN, Attack)
    ✓ At least 1,000 samples per label
    ✓ No missing or infinite values
    ✓ Reasonable balance between classes
    
    Example Good Output:
    ────────────────────
    Label Distribution:
      BENIGN     : 3,245 (52.00%)  ✓✓ Excellent
      Attack     : 2,993 (48.00%)  ✓✓ Excellent
    """)
    
    # Check if data exists
    if os.path.exists('example_data.csv'):
        print("\n✅ Found example_data.csv!")
        response = input("\nRun quality check now? (y/n): ")
        if response.lower() == 'y':
            os.system("python Data_Checker.py example_data.csv")
            pause()
    else:
        print("\n⚠️  example_data.csv not found. Please collect data first.")
        pause()
    
    # ============================================================
    # STEP 3: Model Training
    # ============================================================
    print_step(3, "MODEL TRAINING")
    
    print("""
    Now train the Logistic Regression model on your collected data:
    
    Command:
    ────────
    python Trainer.py -d example_data.csv
    
    What Happens:
    ─────────────
    1. Loads and preprocesses data
    2. Remaps labels to binary (BENIGN vs Attack)
    3. Splits into training (80%) and testing (20%)
    4. Trains Logistic Regression classifier
    5. Evaluates performance
    6. Saves model files:
       - ids_model.pkl (trained model)
       - ids_scaler.pkl (feature scaler)
       - ids_labels.pkl (label encoder)
       - ids_features.pkl (feature names)
       - ids_metadata.pkl (training info)
       - confusion_matrix.png (visualization)
       - feature_importance.png (visualization)
    
    Expected Output:
    ────────────────
    ✅ Overall Accuracy: 90-99%
    ✅ F1-Score for both classes: > 0.85
    ✅ Training completed in seconds
    
    Training Time:
    ──────────────
    - Small dataset (5,000 samples): ~5 seconds
    - Medium dataset (20,000 samples): ~15 seconds
    - Large dataset (100,000 samples): ~1 minute
    """)
    
    if os.path.exists('example_data.csv'):
        response = input("\nTrain model now? (y/n): ")
        if response.lower() == 'y':
            print("\n⏳ Starting training... (this may take a few minutes)")
            os.system("python Trainer.py -d example_data.csv")
            pause()
    else:
        print("\n⚠️  Data file not found. Collect data first.")
        pause()
    
    # ============================================================
    # STEP 4: Verify Model Files
    # ============================================================
    print_step(4, "VERIFY MODEL FILES")
    
    print("""
    Check that all model files were created:
    """)
    
    required_files = [
        'ids_model.pkl',
        'ids_scaler.pkl',
        'ids_labels.pkl',
        'ids_features.pkl',
        'ids_metadata.pkl'
    ]
    
    all_found = True
    for file in required_files:
        if os.path.exists(file):
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} (Missing)")
            all_found = False
    
    if all_found:
        print("\n✅ All model files present! Ready for detection.")
    else:
        print("\n⚠️  Some model files are missing. Please train the model first.")
        pause()
        return
    
    pause()
    
    # ============================================================
    # STEP 5: Real-Time Detection
    # ============================================================
    print_step(5, "REAL-TIME ATTACK DETECTION")
    
    print("""
    Now use the trained model for real-time attack detection!
    
    You need TWO terminals again:
    
    Terminal 1 (Detector):
    ──────────────────────
    python Attack_Detector.py
    
    # You should see:
    # 🚨 NETWORK ATTACK DETECTOR (BENIGN vs Attack)
    # 🚨 STARTING REAL-TIME ATTACK DETECTION
    # ✓ Normal traffic: ... (green text)
    
    Terminal 2 (Test Attacks):
    ──────────────────────────
    # Test Port Scan Detection
    python Attack_Generator.py 127.0.0.1 -a portscan --end-port 500
    
    # Test TCP Flood Detection
    python Attack_Generator.py 127.0.0.1 -a tcp-flood -d 30 -r 100
    
    # Test UDP Flood Detection
    python Attack_Generator.py 127.0.0.1 -a udp-flood -d 30 -r 100
    
    Expected Detection Output:
    ──────────────────────────
    🚨 ATTACK DETECTED!
       Source: 127.0.0.1:52341
       Destination: 127.0.0.1:80
       Protocol: 6
       Packets: 1523
       Bytes: 92380
       Confidence: 96.45%
    
    Alert Logging:
    ──────────────
    All alerts are saved to: intrusion_alerts.log
    
    To Stop:
    ────────
    Press Ctrl+C in Terminal 1
    """)
    
    if all_found:
        response = input("\nStart real-time detection now? (y/n): ")
        if response.lower() == 'y':
            print("\n⚠️  Starting detector... Press Ctrl+C to stop")
            print("⚠️  Open another terminal to run attacks for testing\n")
            time.sleep(2)
            os.system("python Attack_Detector.py")
    else:
        print("\n⚠️  Train model first before detection.")
    
    # ============================================================
    # SUMMARY
    # ============================================================
    print_header("WORKFLOW SUMMARY")
    
    print("""
    Complete IDS Workflow (Binary: BENIGN vs Attack):
    ═════════════════════════════════════════════════════════════
    
    1. ✅ COLLECT DATA
       - Normal traffic: python Data_Collector.py -l BENIGN
       - Attack traffic:  python Data_Collector.py -l Attack
       - Minimum 3,000 flows per label
    
    2. ✅ VERIFY QUALITY
       - python Data_Checker.py collected_data.csv
       - Check balance between BENIGN and Attack
    
    3. ✅ TRAIN MODEL
       - python Trainer.py -d collected_data.csv
       - Uses Logistic Regression (binary classifier)
       - Wait for > 90% accuracy
       - Review confusion matrix
    
    4. ✅ DETECT ATTACKS
       - python Attack_Detector.py
       - Monitor real-time traffic
       - Check intrusion_alerts.log
    
    ═════════════════════════════════════════════════════════════
    
    Tips for Best Results:
    ─────────────────────
    • Collect diverse data (different times, targets, intensities)
    • Balance your dataset (similar amounts of BENIGN and Attack)
    • Train with at least 6,000 total samples (3,000 each)
    • Mix attack types: port scans, TCP floods, UDP floods
    • Test thoroughly before production use
    • Update model regularly with new attack patterns
    
    Performance Expectations:
    ────────────────────────
    • Detection Accuracy: 90-99%
    • False Positive Rate: < 5%
    • Detection Speed: < 100ms per flow
    • Can process 100-1000 packets/second
    
    Common Issues:
    ──────────────
    • Low accuracy → Collect more/better data
    • False positives → Collect more benign traffic
    • False negatives → Collect more attack variations
    • No packets → Run as Administrator/sudo
    
    Next Steps:
    ───────────
    1. Test with different attack methods
    2. Fine-tune by collecting edge cases
    3. Deploy in production environment
    4. Set up automated alerts
    5. Monitor and update regularly
    
    ═════════════════════════════════════════════════════════════
    
    📚 For detailed instructions, see:
       - DATA_COLLECTION_GUIDE.md
       - TRAINING_DETECTION_GUIDE.md
    
    🎉 Your IDS is ready to protect your network!
    
    ═════════════════════════════════════════════════════════════
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Workflow demonstration ended.")
        sys.exit(0)
