#!/usr/bin/env python3
from scapy.all import *
import random
import time
import ipaddress

def create_random_ip():
    """Generate a random IP address (non-private)"""
    while True:
        ip = str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
        # Skip private IP ranges
        if not (ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('192.168.')):
            return ip

def generate_sample_traffic(num_packets=1000, output_file="sample_capture.pcap"):
    """Generate sample network traffic and save to a PCAP file"""
    print(f"Generating {num_packets} sample packets...")
    
    # Create packet list
    packets = []
    
    # Generate some source and destination IPs
    src_ips = [create_random_ip() for _ in range(20)]
    dst_ips = [create_random_ip() for _ in range(50)]
    
    # Add some "suspicious" IPs that will do port scanning
    suspicious_ips = [create_random_ip() for _ in range(3)]
    
    # Common ports
    common_ports = [22, 23, 25, 53, 80, 443, 8080, 8443, 3389]
    
    # Generate timestamps over a 30-minute period
    start_time = time.time() - 1800  # 30 mins ago
    
    # Generate regular traffic
    for i in range(num_packets - 200):  # Reserve 200 packets for port scanning
        # Choose IPs and ports
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(common_ports)
        
        # Randomize timestamp within the 30-minute window
        timestamp = start_time + random.uniform(0, 1800)
        
        # Create packet
        if random.random() < 0.8:  # 80% TCP, 20% UDP
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        else:
            packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        
        # Set packet time
        packet.time = timestamp
        
        packets.append(packet)
    
    # Generate port scanning traffic (suspicious activity)
    for suspicious_ip in suspicious_ips:
        scan_target = random.choice(dst_ips)
        base_time = start_time + random.uniform(0, 1500)  # Sometime in the 30-min window
        
        # Generate 60-70 packets to different ports
        scan_ports = list(range(1, 200))  # First 200 ports
        random.shuffle(scan_ports)
        
        for i, port in enumerate(scan_ports[:random.randint(60, 70)]):
            src_port = random.randint(1024, 65535)
            timestamp = base_time + i * 0.5  # Each scan 0.5 seconds apart
            
            # Create scan packet
            packet = IP(src=suspicious_ip, dst=scan_target) / TCP(sport=src_port, dport=port)
            packet.time = timestamp
            
            packets.append(packet)
    
    # Save packets to PCAP
    wrpcap(output_file, packets)
    print(f"Created sample PCAP file: {output_file}")
    print(f"Sample suspicious IPs (port scanners):")
    for ip in suspicious_ips:
        print(f" - {ip}")

if __name__ == "__main__":
    generate_sample_traffic() 