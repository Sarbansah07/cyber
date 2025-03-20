#!/usr/bin/env python3
from scapy.all import *
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict
import sys
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FileBasedNetworkAnalyzer:
    def __init__(self):
        self.packets = []
        self.suspicious_ips = set()
        self.port_scan_threshold = 10
        self.time_window = 60  # seconds

    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file for network traffic"""
        if not os.path.exists(pcap_file):
            logger.error(f"File not found: {pcap_file}")
            return
        
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            # Read packets from the PCAP file
            scapy_cap = rdpcap(pcap_file)
            logger.info(f"Successfully loaded {len(scapy_cap)} packets")
            
            # Process each packet
            for packet in scapy_cap:
                self.process_packet(packet)
                
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {str(e)}")
    
    def process_packet(self, packet):
        """Process an individual packet"""
        if packet.haslayer(IP):
            packet_info = {
                'timestamp': datetime.fromtimestamp(packet.time),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'flags': packet[IP].flags
            }
            
            if packet.haslayer(TCP):
                packet_info.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_flags': packet[TCP].flags
                })
            elif packet.haslayer(UDP):
                packet_info.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
            
            self.packets.append(packet_info)
            self.analyze_packet(packet_info)
    
    def analyze_packet(self, packet_info):
        """Analyze individual packets for suspicious activity"""
        # Check for port scanning
        if packet_info.get('protocol') == 6:  # TCP
            self.detect_port_scan(packet_info)
        
        # Check for suspicious flags
        if packet_info.get('tcp_flags'):
            self.check_suspicious_flags(packet_info)

    def detect_port_scan(self, packet_info):
        """Detect potential port scanning activity"""
        recent_packets = [p for p in self.packets 
                         if (packet_info['timestamp'] - p['timestamp']).total_seconds() <= self.time_window
                         and p['src_ip'] == packet_info['src_ip']]
        
        unique_ports = len(set(p['dst_port'] for p in recent_packets if 'dst_port' in p))
        
        if unique_ports > self.port_scan_threshold:
            self.suspicious_ips.add(packet_info['src_ip'])
            logger.warning(f"Potential port scan detected from IP: {packet_info['src_ip']}")

    def check_suspicious_flags(self, packet_info):
        """Check for suspicious TCP flags"""
        if packet_info.get('tcp_flags') == 0:  # NULL scan
            self.suspicious_ips.add(packet_info['src_ip'])
            logger.warning(f"NULL scan detected from IP: {packet_info['src_ip']}")

    def generate_report(self):
        """Generate analysis report"""
        if not self.packets:
            logger.info("No packets found for analysis")
            return

        df = pd.DataFrame(self.packets)
        
        # Basic statistics
        logger.info("\n=== Network Traffic Analysis Report ===")
        logger.info(f"Total packets analyzed: {len(self.packets)}")
        logger.info(f"Unique source IPs: {df['src_ip'].nunique()}")
        logger.info(f"Unique destination IPs: {df['dst_ip'].nunique()}")
        
        # Protocol distribution
        protocol_dist = df['protocol'].value_counts()
        logger.info("\nProtocol Distribution:")
        for protocol, count in protocol_dist.items():
            logger.info(f"Protocol {protocol}: {count} packets")

        # Suspicious activity
        if self.suspicious_ips:
            logger.info("\nSuspicious IPs detected:")
            for ip in self.suspicious_ips:
                logger.info(f"- {ip}")

        # Generate traffic visualization
        self.plot_traffic(df)

    def plot_traffic(self, df):
        """Generate traffic visualization"""
        plt.figure(figsize=(12, 6))
        df['timestamp'].value_counts().sort_index().plot()
        plt.title('Network Traffic Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Packets')
        plt.savefig('traffic_analysis.png')
        plt.close()
        logger.info("\nTraffic visualization saved as 'traffic_analysis.png'")

def main():
    if len(sys.argv) < 2:
        print("Usage: python file_based_analyzer.py <pcap_file>")
        print("Example: python file_based_analyzer.py sample_capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    analyzer = FileBasedNetworkAnalyzer()
    analyzer.analyze_pcap(pcap_file)
    analyzer.generate_report()

if __name__ == "__main__":
    main() 