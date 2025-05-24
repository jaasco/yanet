#!/usr/bin/env python3
from scapy.all import Ether, Dot1Q, IP, TCP, Raw, wrpcap, rdpcap
import os


def create_packet():
    eth = Ether(src="00:00:00:88:88:88", dst="00:11:22:33:44:55") / Dot1Q(vlan=100)
    ip = IP(src="10.0.0.1", dst="10.0.0.2")
    tcp = TCP(sport=12345, dport=443, flags="PA", seq=1000, ack=0)
    packet = eth / ip / tcp 
    return packet

def create_pcap(output_path):
    packet = create_packet()
    wrpcap(output_path, [packet])
    print("PCAP file 'send.pcap' created successfully")

if __name__ == "__main__":
    output_path = os.path.join(os.path.dirname(__file__), "send.pcap")
    create_pcap(output_path)
    packets = rdpcap(output_path)

    for pkt in packets:
        if Dot1Q in pkt and IP in pkt and TCP in pkt and Raw in pkt:
            print("VLAN ID:", pkt[Dot1Q].vlan)
            print("Source IP:", pkt[IP].src)
            print("Dest IP:", pkt[IP].dst)
            print("TCP Sport:", pkt[TCP].sport)
            print("TCP Dport:", pkt[TCP].dport)
            print("-" * 40)