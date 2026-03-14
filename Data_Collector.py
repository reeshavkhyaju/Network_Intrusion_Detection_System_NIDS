#!/usr/bin/python3
"""
Network Traffic Data Collector for IDS Training
Collects labeled network traffic data for binary classification:
- Attack traffic
- Benign (normal) traffic
"""

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from time import time
from datetime import datetime
import logging
import argparse
import signal
import sys
import os

class NetworkDataCollector:
    def __init__(self, label="BENIGN", output_file="collected_data.csv", flow_timeout=120):
        """
        Initialize the data collector
        
        Args:
            label: Label for the collected traffic (BENIGN or Attack)
            output_file: Output CSV file name
            flow_timeout: Flow timeout in seconds (default 120s like CICIDS2017)
        """
        self.label = label
        self.output_file = output_file
        self.flow_timeout = flow_timeout
        self.flows = {}
        self.collected_flows = []
        self.packet_count = 0
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        logging.info(f"Data Collector initialized with label: {self.label}")
        logging.info(f"Output file: {self.output_file}")
        logging.info(f"Flow timeout: {self.flow_timeout} seconds")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        logging.info("\n[!] Stopping data collection...")
        self.save_data()
        sys.exit(0)
    
    def get_flow_key(self, packet):
        """
        Extract flow key from packet (5-tuple)
        Returns: (src_ip, dst_ip, src_port, dst_port, protocol)
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
        """
        Extract features from flow data matching CICIDS2017 format
        """
        try:
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            
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
                'Idle Min': 0,     # Placeholder
                'Label': self.label
            }
            
            return features
            
        except Exception as e:
            logging.error(f"Error extracting features: {e}")
            return None
    
    def process_completed_flow(self, flow_key):
        """Process and save a completed flow"""
        try:
            flow_data = self.flows[flow_key]
            features = self.extract_features(flow_key, flow_data)
            
            if features:
                self.collected_flows.append(features)
                logging.info(f"Flow processed: {flow_key[0]}:{flow_key[2]} -> {flow_key[1]}:{flow_key[3]} "
                           f"| Packets: {features['Total Fwd Packets'] + features['Total Backward Packets']} "
                           f"| Label: {self.label}")
            
            del self.flows[flow_key]
            
        except Exception as e:
            logging.error(f"Error processing flow: {e}")
    
    def analyze_packet(self, packet):
        """Analyze each captured packet"""
        try:
            flow_key = self.get_flow_key(packet)
            if flow_key is None:
                return
            
            current_time = time()
            self.packet_count += 1
            
            # Extract base flow key (without direction flag)
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
            
            # Update flow statistics based on direction
            if is_forward:
                flow['fwd_packets'] += 1
                flow['fwd_bytes'] += packet_len
                flow['fwd_packet_length_max'] = max(flow['fwd_packet_length_max'], packet_len)
                flow['fwd_packet_length_min'] = min(flow['fwd_packet_length_min'], packet_len)
                
                if flow['fwd_packets'] > 1:
                    iat = (current_time - flow['fwd_last_seen']) * 1000000  # microseconds
                    flow['fwd_iat_total'] += iat
                flow['fwd_last_seen'] = current_time
            else:
                flow['bwd_packets'] += 1
                flow['bwd_bytes'] += packet_len
                flow['bwd_packet_length_max'] = max(flow['bwd_packet_length_max'], packet_len)
                flow['bwd_packet_length_min'] = min(flow['bwd_packet_length_min'], packet_len)
                
                if flow['bwd_packets'] > 1:
                    iat = (current_time - flow['bwd_last_seen']) * 1000000  # microseconds
                    flow['bwd_iat_total'] += iat
                flow['bwd_last_seen'] = current_time
            
            # Extract TCP flags
            if packet.haslayer(TCP):
                flags = packet[TCP].flags
                flow['SYN'] += int(flags & 0x02 != 0)
                flow['ACK'] += int(flags & 0x10 != 0)
                flow['RST'] += int(flags & 0x04 != 0)
                flow['FIN'] += int(flags & 0x01 != 0)
                
                if flags & 0x08:  # PSH flag
                    if is_forward:
                        flow['PSH_fwd'] += 1
                    else:
                        flow['PSH_bwd'] += 1
                
                if flags & 0x20:  # URG flag
                    if is_forward:
                        flow['URG_fwd'] += 1
                    else:
                        flow['URG_bwd'] += 1
            
            flow['last_seen'] = current_time
            
            # Check for timed-out flows
            completed_flows = [k for k, v in self.flows.items() 
                              if current_time - v['last_seen'] > self.flow_timeout]
            
            for completed_key in completed_flows:
                self.process_completed_flow(completed_key)
            
            # Print statistics every 100 packets
            if self.packet_count % 100 == 0:
                logging.info(f"Packets captured: {self.packet_count} | "
                           f"Active flows: {len(self.flows)} | "
                           f"Completed flows: {len(self.collected_flows)}")
                
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
    
    def save_data(self):
        """Save collected data to CSV"""
        try:
            # Process remaining flows
            for flow_key in list(self.flows.keys()):
                self.process_completed_flow(flow_key)
            
            if len(self.collected_flows) == 0:
                logging.warning("No flows collected to save!")
                return
            
            df = pd.DataFrame(self.collected_flows)
            
            # Save to CSV
            if os.path.exists(self.output_file):
                # Append to existing file
                df.to_csv(self.output_file, mode='a', header=False, index=False)
                logging.info(f"Appended {len(df)} flows to {self.output_file}")
            else:
                # Create new file
                df.to_csv(self.output_file, index=False)
                logging.info(f"Created {self.output_file} with {len(df)} flows")
            
            logging.info(f"Total packets captured: {self.packet_count}")
            logging.info(f"Total flows saved: {len(self.collected_flows)}")
            
            # Show label distribution
            logging.info(f"\nLabel distribution:")
            logging.info(f"  {self.label}: {len(df)} flows")
            
        except Exception as e:
            logging.error(f"Error saving data: {e}")
    
    def start_capture(self, interface=None, filter_str=None):
        """Start packet capture"""
        try:
            logging.info(f"\n{'='*60}")
            logging.info(f"Starting packet capture...")
            logging.info(f"Label: {self.label}")
            if interface:
                logging.info(f"Interface: {interface}")
            if filter_str:
                logging.info(f"Filter: {filter_str}")
            logging.info(f"Press Ctrl+C to stop and save data")
            logging.info(f"{'='*60}\n")
            
            sniff(prn=self.analyze_packet, 
                  iface=interface, 
                  filter=filter_str,
                  store=False)
                  
        except Exception as e:
            logging.error(f"Error during capture: {e}")
            self.save_data()


def print_attack_guide():
    """Print guide for generating attacks"""
    guide = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║          ATTACK TRAFFIC GENERATION GUIDE                      ║
    ║          (Binary Classification: BENIGN vs Attack)            ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    All attack types are labeled as 'Attack' for binary classification.
    You can use any of the following methods to generate attack traffic:
    
    ┌─────────────────────────────────────────────────────────────┐
    │ ATTACK METHODS (all labeled as 'Attack')                    │
    └─────────────────────────────────────────────────────────────┘
    
    1. PORT SCAN:
    
    Using Attack_Generator.py:
      python Attack_Generator.py <target_ip> -a portscan --end-port 1000
    
    Using Nmap:
      nmap -sS -p 1-65535 <target_ip>
    
    2. TCP FLOOD:
    
    Using Attack_Generator.py:
      python Attack_Generator.py <target_ip> -a tcp-flood -d 120 -r 100
    
    Using hping3:
      sudo hping3 -S -p 80 --flood <target_ip>
    
    3. UDP FLOOD:
    
    Using Attack_Generator.py:
      python Attack_Generator.py <target_ip> -a udp-flood -d 120 -r 100
    
    Using hping3:
      sudo hping3 --udp -p 53 --flood <target_ip>
    
    ┌─────────────────────────────────────────────────────────────┐
    │ BENIGN (Normal Traffic)                                     │
    └─────────────────────────────────────────────────────────────┘
    
    Just browse websites, use applications normally:
      • Web browsing (HTTP/HTTPS)
      • File downloads
      • Video streaming
      • SSH connections
      • Email (SMTP/IMAP)
    
    ═══════════════════════════════════════════════════════════════
    IMPORTANT NOTES:
    ═══════════════════════════════════════════════════════════════
    
    ⚠️  WARNING: Only perform attacks on systems you own or have
        explicit permission to test! Unauthorized attacks are illegal.
    
    📝 WORKFLOW:
       1. Collect BENIGN: python Data_Collector.py -l BENIGN
          (Browse normally for 10+ minutes, then Ctrl+C)
       2. Collect Attack:  python Data_Collector.py -l Attack
          (Run any attack from another terminal, then Ctrl+C)
       3. Repeat step 2 with different attack methods for variety
    
    🎯 RECOMMENDATIONS:
       • Collect at least 3,000 BENIGN flows
       • Collect at least 3,000 Attack flows (mix of types)
       • Use different target ports and IPs for variety
       • Mix attack intensities (slow/fast)
    
    """
    print(guide)


def main():
    parser = argparse.ArgumentParser(
        description='Network Traffic Data Collector for IDS Training',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-l', '--label', 
                       choices=['BENIGN', 'Attack'],
                       default='BENIGN',
                       help='Traffic label (default: BENIGN)')
    
    parser.add_argument('-o', '--output',
                       default='collected_data.csv',
                       help='Output CSV file (default: collected_data.csv)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=120,
                       help='Flow timeout in seconds (default: 120)')
    
    parser.add_argument('-i', '--interface',
                       help='Network interface to capture on (default: all)')
    
    parser.add_argument('-f', '--filter',
                       help='BPF filter string (e.g., "tcp port 80")')
    
    parser.add_argument('--guide',
                       action='store_true',
                       help='Show attack generation guide and exit')
    
    args = parser.parse_args()
    
    if args.guide:
        print_attack_guide()
        return
    
    # Create data collector
    collector = NetworkDataCollector(
        label=args.label,
        output_file=args.output,
        flow_timeout=args.timeout
    )
    
    # Start capturing
    collector.start_capture(
        interface=args.interface,
        filter_str=args.filter
    )


if __name__ == "__main__":
    main()
