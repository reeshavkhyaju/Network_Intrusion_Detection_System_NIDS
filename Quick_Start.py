#!/usr/bin/python3
"""
Quick Start Helper for IDS Data Collection
Interactive script to guide data collection process
"""

import os
import sys
import time

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    Network Intrusion Detection System (NIDS)             ║
    ║           Data Collection Helper                         ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_menu():
    menu = """
    What would you like to do?
    
    1. 📖 Read the Data Collection Guide
    2. 🔍 Check prerequisites
    3. 📊 Start Data Collection (Collector)
    4. 💥 Generate Attacks (Attacker)
    5. ✅ Check collected data quality
    6. 🔗 Merge multiple CSV files
    7. 🎓 Train the model
    8. 🚨 Run Real-Time Detection
    9. ❓ Show attack generation guide
    0. 🚪 Exit
    """
    print(menu)

def check_prerequisites():
    print("\n" + "="*60)
    print("🔍 CHECKING PREREQUISITES")
    print("="*60 + "\n")
    
    issues = []
    
    # Check Python version
    print("1. Checking Python version...")
    if sys.version_info >= (3, 7):
        print(f"   ✅ Python {sys.version_info.major}.{sys.version_info.minor} (OK)")
    else:
        print(f"   ❌ Python {sys.version_info.major}.{sys.version_info.minor} (Need 3.7+)")
        issues.append("Upgrade Python to 3.7 or higher")
    
    # Check required modules
    print("\n2. Checking required Python packages...")
    required_packages = ['scapy', 'pandas', 'numpy', 'sklearn', 'joblib']
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package} (Not installed)")
            issues.append(f"Install {package}: pip install {package}")
    
    # Check for admin/sudo
    print("\n3. Checking privileges...")
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("   ✅ Running as Administrator")
            else:
                print("   ⚠️  Not running as Administrator")
                issues.append("Run PowerShell/CMD as Administrator for packet capture")
        except:
            print("   ⚠️  Cannot determine admin status")
    else:  # Linux/Mac
        if os.geteuid() == 0:
            print("   ✅ Running as root/sudo")
        else:
            print("   ⚠️  Not running as root")
            issues.append("Use 'sudo' for packet capture")
    
    # Check required files
    print("\n4. Checking required files...")
    required_files = [
        'Data_Collector.py',
        'Attack_Generator.py',
        'Data_Checker.py',
        'Trainer.py',
        'Attack_Detector.py'
    ]
    
    for file in required_files:
        if os.path.exists(file):
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} (Missing)")
            issues.append(f"Missing file: {file}")
    
    # Summary
    print("\n" + "="*60)
    if len(issues) == 0:
        print("✅ All prerequisites met! You're ready to go.")
    else:
        print("⚠️  Issues found:\n")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
    print("="*60)

def start_data_collection():
    print("\n" + "="*60)
    print("📊 DATA COLLECTION")
    print("="*60 + "\n")
    
    print("Select traffic type to collect:")
    print("  1. BENIGN (Normal traffic)")
    print("  2. PortScan")
    print("  3. DoS-TCP")
    print("  4. DoS-UDP")
    print("  0. Back")
    
    choice = input("\nYour choice: ").strip()
    
    label_map = {
        '1': 'BENIGN',
        '2': 'PortScan',
        '3': 'DoS-TCP',
        '4': 'DoS-UDP'
    }
    
    if choice not in label_map:
        return
    
    label = label_map[choice]
    
    print(f"\n📝 Selected: {label}")
    
    # Get filename
    filename = input("Output CSV file (default: collected_data.csv): ").strip()
    if not filename:
        filename = "collected_data.csv"
    
    # Get timeout
    timeout = input("Flow timeout in seconds (default: 120): ").strip()
    if not timeout:
        timeout = "120"
    
    # Build command
    cmd = f"python Data_Collector.py -l {label} -o {filename} -t {timeout}"
    
    print("\n" + "="*60)
    print(f"Command: {cmd}")
    print("="*60)
    print("\n⚠️  Press Ctrl+C to stop and save data")
    
    input("\nPress Enter to start...")
    
    os.system(cmd)

def generate_attacks():
    print("\n" + "="*60)
    print("💥 ATTACK GENERATION")
    print("="*60 + "\n")
    
    print("⚠️  WARNING: Only attack systems you own or have permission to test!\n")
    
    target_ip = input("Target IP address: ").strip()
    if not target_ip:
        print("❌ Target IP required!")
        return
    
    print("\nSelect attack type:")
    print("  1. Port Scan")
    print("  2. DoS TCP (SYN Flood)")
    print("  3. DoS UDP Flood")
    print("  0. Back")
    
    choice = input("\nYour choice: ").strip()
    
    if choice == '1':
        # Port Scan
        port_range = input("Port range (default: 1-1024): ").strip()
        if not port_range:
            start_port = "1"
            end_port = "1024"
        else:
            parts = port_range.split('-')
            start_port = parts[0]
            end_port = parts[1] if len(parts) > 1 else parts[0]
        
        cmd = f"python Attack_Generator.py {target_ip} -a portscan --start-port {start_port} --end-port {end_port}"
    
    elif choice == '2':
        # DoS TCP
        port = input("Target port (default: 80): ").strip() or "80"
        duration = input("Duration in seconds (default: 120): ").strip() or "120"
        rate = input("Packets/sec (0 for flood, default: 500): ").strip() or "500"
        
        cmd = f"python Attack_Generator.py {target_ip} -a dos-tcp -p {port} -d {duration} -r {rate}"
    
    elif choice == '3':
        # DoS UDP
        port = input("Target port (default: 53): ").strip() or "53"
        duration = input("Duration in seconds (default: 120): ").strip() or "120"
        rate = input("Packets/sec (0 for flood, default: 500): ").strip() or "500"
        
        cmd = f"python Attack_Generator.py {target_ip} -a dos-udp -p {port} -d {duration} -r {rate}"
    
    else:
        return
    
    print("\n" + "="*60)
    print(f"Command: {cmd}")
    print("="*60)
    
    input("\nPress Enter to start...")
    
    os.system(cmd)

def check_data_quality():
    print("\n" + "="*60)
    print("✅ DATA QUALITY CHECK")
    print("="*60 + "\n")
    
    filename = input("CSV file to check (default: collected_data.csv): ").strip()
    if not filename:
        filename = "collected_data.csv"
    
    if not os.path.exists(filename):
        print(f"\n❌ File '{filename}' not found!")
        return
    
    cmd = f"python Data_Checker.py {filename}"
    os.system(cmd)

def merge_files():
    print("\n" + "="*60)
    print("🔗 MERGE CSV FILES")
    print("="*60 + "\n")
    
    files = input("CSV files to merge (space-separated): ").strip()
    if not files:
        print("❌ No files specified!")
        return
    
    output = input("Output file (default: merged_data.csv): ").strip()
    if not output:
        output = "merged_data.csv"
    
    cmd = f"python Data_Checker.py --merge {files} -o {output}"
    os.system(cmd)

def train_model():
    print("\n" + "="*60)
    print("🎓 TRAIN MODEL")
    print("="*60 + "\n")
    
    if not os.path.exists('Trainer.py'):
        print("❌ Trainer.py not found!")
        return
    
    print("⚠️  Make sure Trainer.py is configured to use your collected data\n")
    
    input("Press Enter to start training...")
    
    os.system("python Trainer.py")

def run_detection():
    print("\n" + "="*60)
    print("🚨 REAL-TIME DETECTION")
    print("="*60 + "\n")
    
    if not os.path.exists('Attack_Detector.py'):
        print("❌ Attack_Detector.py not found!")
        return
    
    if not os.path.exists('ids_model.pkl'):
        print("⚠️  Model not found! Train the model first.\n")
        return
    
    print("⚠️  This will monitor network traffic in real-time")
    print("    Press Ctrl+C to stop\n")
    
    input("Press Enter to start...")
    
    os.system("python Attack_Detector.py")

def show_attack_guide():
    os.system("python Data_Collector.py --guide")

def open_guide():
    guide_file = "DATA_COLLECTION_GUIDE.md"
    
    if os.path.exists(guide_file):
        if os.name == 'nt':  # Windows
            os.system(f'start notepad {guide_file}')
        elif sys.platform == 'darwin':  # macOS
            os.system(f'open {guide_file}')
        else:  # Linux
            os.system(f'xdg-open {guide_file} || cat {guide_file}')
    else:
        print(f"❌ Guide file '{guide_file}' not found!")

def main():
    while True:
        print_banner()
        print_menu()
        
        choice = input("\nEnter your choice (0-9): ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            break
        elif choice == '1':
            open_guide()
        elif choice == '2':
            check_prerequisites()
        elif choice == '3':
            start_data_collection()
        elif choice == '4':
            generate_attacks()
        elif choice == '5':
            check_data_quality()
        elif choice == '6':
            merge_files()
        elif choice == '7':
            train_model()
        elif choice == '8':
            run_detection()
        elif choice == '9':
            show_attack_guide()
        else:
            print("\n❌ Invalid choice! Please select 0-9.")
        
        input("\nPress Enter to continue...")
        
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
