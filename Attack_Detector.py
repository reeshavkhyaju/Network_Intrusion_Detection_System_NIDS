#!/usr/bin/python3
"""
Real-Time Network Attack Detector
Monitors network traffic and detects attacks using trained Logistic Regression model
Binary classification: BENIGN vs Attack
"""

from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import pandas as pd
from time import time
from datetime import datetime
import logging
import argparse
import signal
import sys
import os

class AttackDetector:
    def __init__(self, model_dir='.', flow_timeout=120):
        """
        Initialize the Attack Detector
        
        Args:
            model_dir: Directory containing model files
            flow_timeout: Flow timeout in seconds
        """
        self.model_dir = model_dir
        self.flow_timeout = flow_timeout
        self.flows = {}
        self.packet_count = 0
        self.alert_count = 0
        self.running = False
        
        # Logging setup
        self.LOG_FILE = 'intrusion_alerts.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.LOG_FILE),
                logging.StreamHandler()
            ]
        )
        
        # Load model and related files
        self.load_model()
        
        # Register signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        logging.info("\n[!] Stopping attack detector...")
        self.running = False
        self.print_statistics()
        sys.exit(0)
    
    def load_model(self):
        """Load trained model and related objects"""
        print("\n" + "="*70)
        print("🚨 NETWORK ATTACK DETECTOR (BENIGN vs Attack)")
        print("="*70)
        print("\n📂 Loading model...")
        
        try:
            # Load model
            model_file = os.path.join(self.model_dir, 'ids_model.pkl')
            if not os.path.exists(model_file):
                raise FileNotFoundError(f"Model file not found: {model_file}")
            self.model = joblib.load(model_file)
            print(f"✅ Model loaded from: {model_file}")
            
            # Load scaler
            scaler_file = os.path.join(self.model_dir, 'ids_scaler.pkl')
            if not os.path.exists(scaler_file):
                raise FileNotFoundError(f"Scaler file not found: {scaler_file}")
            self.scaler = joblib.load(scaler_file)
            print(f"✅ Scaler loaded from: {scaler_file}")
            
            # Load label encoder
            label_file = os.path.join(self.model_dir, 'ids_labels.pkl')
            if not os.path.exists(label_file):
                raise FileNotFoundError(f"Label file not found: {label_file}")
            self.label_encoder = joblib.load(label_file)
            print(f"✅ Label encoder loaded from: {label_file}")
            
            # Load feature names
            features_file = os.path.join(self.model_dir, 'ids_features.pkl')
            if not os.path.exists(features_file):
                raise FileNotFoundError(f"Features file not found: {features_file}")
            self.feature_names = joblib.load(features_file)
            print(f"✅ Feature names loaded from: {features_file}")
            
            # Load metadata (optional)
            try:
                metadata_file = os.path.join(self.model_dir, 'ids_metadata.pkl')
                self.metadata = joblib.load(metadata_file)
                print(f"✅ Metadata loaded from: {metadata_file}")
                
                print(f"\n📋 Model Information:")
                print(f"   Algorithm: {self.metadata.get('algorithm', 'Unknown')}")
                print(f"   Training Date: {self.metadata.get('training_date', 'Unknown')}")
                print(f"   Features: {self.metadata.get('num_features', 'Unknown')}")
                print(f"   Classes: {', '.join(self.metadata.get('classes', []))}")
            except:
                pass
            
            print(f"\n✅ Detection system ready!")
            print(f"   Classification: Binary (BENIGN vs Attack)")
            print(f"   Classes: {', '.join(self.label_encoder.classes_)}")
            print(f"   Alert log: {self.LOG_FILE}")
            
        except Exception as e:
            print(f"\n❌ Error loading model: {e}")
            print("\nPlease train the model first using:")
            print("  python Trainer.py -d collected_data.csv")
            sys.exit(1)
    
    def get_flow_key(self, packet):
        """
        Extract flow key from packet (5-tuple)
        Returns: (src_ip, dst_ip, src_port, dst_port, protocol, is_forward)
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            src_port = 0
            dst_port = 0
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Create bidirectional flow key (normalize direction)
            if (src_ip, src_port) < (dst_ip, dst_port):
                return (src_ip, dst_ip, src_port, dst_port, protocol, True)
            else:
                return (dst_ip, src_ip, dst_port, src_port, protocol, False)
                
        except Exception as e:
            logging.error(f"Error in get_flow_key: {e}")
            return None
    
    def extract_features(self, flow_key, flow_data):
        """Extract features from flow data"""
        try:
            duration = flow_data['last_seen'] - flow_data['start_time']
            if duration == 0:
                duration = 0.000001  # Avoid division by zero
            
            total_packets = flow_data['fwd_packets'] + flow_data['bwd_packets']
            total_bytes = flow_data['fwd_bytes'] + flow_data['bwd_bytes']
            
            # Calculate packet lengths
            fwd_packet_length_max = flow_data['fwd_packet_length_max']
            fwd_packet_length_min = flow_data['fwd_packet_length_min']
            fwd_packet_length_mean = (flow_data['fwd_bytes'] / flow_data['fwd_packets'] 
                                     if flow_data['fwd_packets'] > 0 else 0)
            
            bwd_packet_length_max = flow_data['bwd_packet_length_max']
            bwd_packet_length_min = flow_data['bwd_packet_length_min']
            bwd_packet_length_mean = (flow_data['bwd_bytes'] / flow_data['bwd_packets'] 
                                     if flow_data['bwd_packets'] > 0 else 0)
            
            # Calculate inter-arrival times
            fwd_iat_mean = (flow_data['fwd_iat_total'] / (flow_data['fwd_packets'] - 1)
                           if flow_data['fwd_packets'] > 1 else 0)
            bwd_iat_mean = (flow_data['bwd_iat_total'] / (flow_data['bwd_packets'] - 1)
                           if flow_data['bwd_packets'] > 1 else 0)
            
            features = {
                'Flow Duration': int(duration * 1000000),  # microseconds
                'Total Fwd Packets': flow_data['fwd_packets'],
                'Total Backward Packets': flow_data['bwd_packets'],
                'Total Length of Fwd Packets': flow_data['fwd_bytes'],
                'Total Length of Bwd Packets': flow_data['bwd_bytes'],
                'Fwd Packet Length Max': fwd_packet_length_max,
                'Fwd Packet Length Min': fwd_packet_length_min,
                'Fwd Packet Length Mean': fwd_packet_length_mean,
                'Bwd Packet Length Max': bwd_packet_length_max,
                'Bwd Packet Length Min': bwd_packet_length_min,
                'Bwd Packet Length Mean': bwd_packet_length_mean,
                'Flow Bytes/s': total_bytes / duration,
                'Flow Packets/s': total_packets / duration,
                'Flow IAT Mean': (duration / (total_packets - 1) * 1000000 
                                 if total_packets > 1 else 0),
                'Fwd IAT Mean': fwd_iat_mean,
                'Bwd IAT Mean': bwd_iat_mean,
                'Fwd PSH Flags': flow_data['PSH_fwd'],
                'Bwd PSH Flags': flow_data['PSH_bwd'],
                'Fwd URG Flags': flow_data['URG_fwd'],
                'Bwd URG Flags': flow_data['URG_bwd'],
                'FIN Flag Count': flow_data['FIN'],
                'SYN Flag Count': flow_data['SYN'],
                'RST Flag Count': flow_data['RST'],
                'PSH Flag Count': flow_data['PSH_fwd'] + flow_data['PSH_bwd'],
                'ACK Flag Count': flow_data['ACK'],
                'URG Flag Count': flow_data['URG_fwd'] + flow_data['URG_bwd'],
                'Down/Up Ratio': (flow_data['bwd_packets'] / flow_data['fwd_packets'] 
                                 if flow_data['fwd_packets'] > 0 else 0),
                'Average Packet Size': total_bytes / total_packets if total_packets > 0 else 0,
                'Fwd Segment Size Avg': fwd_packet_length_mean,
                'Bwd Segment Size Avg': bwd_packet_length_mean,
                'Subflow Fwd Packets': flow_data['fwd_packets'],
                'Subflow Fwd Bytes': flow_data['fwd_bytes'],
                'Subflow Bwd Packets': flow_data['bwd_packets'],
                'Subflow Bwd Bytes': flow_data['bwd_bytes'],
                'Init_Win_bytes_forward': flow_data['init_win_bytes_fwd'],
                'Init_Win_bytes_backward': flow_data['init_win_bytes_bwd'],
                'Active Mean': 0,  # Placeholder
                'Active Std': 0,   # Placeholder
                'Active Max': 0,   # Placeholder
                'Active Min': 0,   # Placeholder
                'Idle Mean': 0,    # Placeholder
                'Idle Std': 0,     # Placeholder
                'Idle Max': 0,     # Placeholder
                'Idle Min': 0      # Placeholder
            }
            
            return features
            
        except Exception as e:
            logging.error(f"Error extracting features: {e}")
            return None
    
    def detect_attack(self, flow_key):
        """Detect attack in completed flow"""
        try:
            flow_data = self.flows[flow_key]
            features_dict = self.extract_features(flow_key, flow_data)
            
            if features_dict is None:
                return
            
            # Create DataFrame with correct feature order
            features_df = pd.DataFrame([features_dict])
            
            # Ensure feature order matches training
            features_df = features_df[self.feature_names]
            
            # Handle infinite and NaN values
            features_df = features_df.replace([np.inf, -np.inf], 0)
            features_df = features_df.fillna(0)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            attack_type = self.label_encoder.inverse_transform([prediction])[0]
            
            # Get prediction probability if available
            confidence = None
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features_scaled)[0]
                confidence = max(probabilities) * 100
            
            # Extract flow information
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            
            # Format alert message
            if attack_type == 'Attack':
                self.alert_count += 1
                
                alert_msg = (
                    f"🚨 ATTACK DETECTED!\n"
                    f"   Source: {src_ip}:{src_port}\n"
                    f"   Destination: {dst_ip}:{dst_port}\n"
                    f"   Protocol: {protocol}\n"
                    f"   Packets: {flow_data['fwd_packets'] + flow_data['bwd_packets']}\n"
                    f"   Bytes: {flow_data['fwd_bytes'] + flow_data['bwd_bytes']}"
                )
                
                if confidence:
                    alert_msg += f"\n   Confidence: {confidence:.2f}%"
                
                # Print colored alert
                print(f"\033[31m{alert_msg}\033[0m\n")
                
                # Log alert
                logging.warning(f"ATTACK DETECTED | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
            else:
                # Normal traffic (only log occasionally to reduce noise)
                if self.packet_count % 100 == 0:
                    msg = f"✓ Normal traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    print(f"\033[32m{msg}\033[0m")
            
            # Clean up flow
            del self.flows[flow_key]
            
        except Exception as e:
            logging.error(f"Error detecting attack: {e}")
    
    def analyze_packet(self, packet):
        """Analyze each captured packet"""
        try:
            flow_key = self.get_flow_key(packet)
            if flow_key is None:
                return
            
            current_time = time()
            self.packet_count += 1
            
            # Extract base flow key
            base_key = flow_key[:5]
            is_forward = flow_key[5]
            
            # Initialize flow if new
            if base_key not in self.flows:
                self.flows[base_key] = {
                    'start_time': current_time,
                    'last_seen': current_time,
                    'fwd_packets': 0,
                    'bwd_packets': 0,
                    'fwd_bytes': 0,
                    'bwd_bytes': 0,
                    'fwd_packet_length_max': 0,
                    'fwd_packet_length_min': float('inf'),
                    'bwd_packet_length_max': 0,
                    'bwd_packet_length_min': float('inf'),
                    'fwd_iat_total': 0,
                    'bwd_iat_total': 0,
                    'fwd_last_seen': current_time,
                    'bwd_last_seen': current_time,
                    'SYN': 0,
                    'ACK': 0,
                    'RST': 0,
                    'FIN': 0,
                    'PSH_fwd': 0,
                    'PSH_bwd': 0,
                    'URG_fwd': 0,
                    'URG_bwd': 0,
                    'init_win_bytes_fwd': 0,
                    'init_win_bytes_bwd': 0,
                    'protocol': base_key[4]
                }
                
                # Capture initial window size
                if packet.haslayer(TCP):
                    if is_forward:
                        self.flows[base_key]['init_win_bytes_fwd'] = packet[TCP].window
                    else:
                        self.flows[base_key]['init_win_bytes_bwd'] = packet[TCP].window
            
            flow = self.flows[base_key]
            packet_len = len(packet)
            
            # Update flow statistics
            if is_forward:
                flow['fwd_packets'] += 1
                flow['fwd_bytes'] += packet_len
                flow['fwd_packet_length_max'] = max(flow['fwd_packet_length_max'], packet_len)
                flow['fwd_packet_length_min'] = min(flow['fwd_packet_length_min'], packet_len)
                
                if flow['fwd_packets'] > 1:
                    iat = (current_time - flow['fwd_last_seen']) * 1000000
                    flow['fwd_iat_total'] += iat
                flow['fwd_last_seen'] = current_time
            else:
                flow['bwd_packets'] += 1
                flow['bwd_bytes'] += packet_len
                flow['bwd_packet_length_max'] = max(flow['bwd_packet_length_max'], packet_len)
                flow['bwd_packet_length_min'] = min(flow['bwd_packet_length_min'], packet_len)
                
                if flow['bwd_packets'] > 1:
                    iat = (current_time - flow['bwd_last_seen']) * 1000000
                    flow['bwd_iat_total'] += iat
                flow['bwd_last_seen'] = current_time
            
            # Extract TCP flags
            if packet.haslayer(TCP):
                flags = packet[TCP].flags
                flow['SYN'] += int(flags & 0x02 != 0)
                flow['ACK'] += int(flags & 0x10 != 0)
                flow['RST'] += int(flags & 0x04 != 0)
                flow['FIN'] += int(flags & 0x01 != 0)
                
                if flags & 0x08:
                    if is_forward:
                        flow['PSH_fwd'] += 1
                    else:
                        flow['PSH_bwd'] += 1
                
                if flags & 0x20:
                    if is_forward:
                        flow['URG_fwd'] += 1
                    else:
                        flow['URG_bwd'] += 1
            
            flow['last_seen'] = current_time
            
            # Check for completed flows
            completed_flows = [k for k, v in self.flows.items() 
                              if current_time - v['last_seen'] > self.flow_timeout]
            
            for completed_key in completed_flows:
                self.detect_attack(completed_key)
            
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
    
    def print_statistics(self):
        """Print detection statistics"""
        print("\n" + "="*70)
        print("📊 DETECTION STATISTICS")
        print("="*70)
        print(f"Total packets analyzed: {self.packet_count:,}")
        print(f"Active flows: {len(self.flows):,}")
        print(f"Attacks detected: {self.alert_count:,}")
        print(f"Alerts logged to: {self.LOG_FILE}")
        print("="*70)
    
    def start_detection(self, interface=None, filter_str=None):
        """Start real-time detection"""
        try:
            print("\n" + "="*70)
            print("🚨 STARTING REAL-TIME ATTACK DETECTION (BENIGN vs Attack)")
            print("="*70)
            print(f"Flow timeout: {self.flow_timeout} seconds")
            if interface:
                print(f"Interface: {interface}")
            if filter_str:
                print(f"Filter: {filter_str}")
            print(f"\n⚠️  Press Ctrl+C to stop\n")
            print("="*70 + "\n")
            
            self.running = True
            
            sniff(prn=self.analyze_packet,
                  iface=interface,
                  filter=filter_str,
                  store=False)
                  
        except Exception as e:
            logging.error(f"Error during detection: {e}")
            self.print_statistics()


def main():
    parser = argparse.ArgumentParser(
        description='Real-Time Network Attack Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-m', '--model-dir',
                       default='.',
                       help='Directory containing model files (default: current directory)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=120,
                       help='Flow timeout in seconds (default: 120)')
    
    parser.add_argument('-i', '--interface',
                       help='Network interface to monitor (default: all)')
    
    parser.add_argument('-f', '--filter',
                       help='BPF filter string (e.g., "tcp port 80")')
    
    args = parser.parse_args()
    
    # Create detector
    detector = AttackDetector(
        model_dir=args.model_dir,
        flow_timeout=args.timeout
    )
    
    # Start detection
    detector.start_detection(
        interface=args.interface,
        filter_str=args.filter
    )


if __name__ == "__main__":
    main()
