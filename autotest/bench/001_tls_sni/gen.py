#!/usr/bin/env python3
from scapy.all import Ether, Dot1Q, IP, TCP, Raw, wrpcap, rdpcap
import os
import struct

# Define multiple SNI cases
sni_list = [
    "example.com",           # normal
    "a.io",                  # short
    "very.very.long.sni.example.com",  # long
    "",                      # empty SNI (technically invalid, but testable)
]

def create_tls_clienthello(server_name_str):
    server_name = server_name_str.encode('utf-8')

    tls_record_header = b'\x16\x03\x01\x00\x00'
    handshake_header = b'\x01\x00\x00\x00'
    client_version = b'\x03\x03'
    client_random = os.urandom(32)
    session_id_length = b'\x00'
    session_id = b''
    cipher_suites_length = b'\x00\x02'
    cipher_suites = b'\xC0\x2F'
    compression_methods_length = b'\x01'
    compression_methods = b'\x00'

    server_name_length = struct.pack('>H', len(server_name))
    sni_entry = b'\x00' + server_name_length + server_name
    sni_list_length = struct.pack('>H', len(sni_entry))
    sni_ext = b'\x00\x00' + struct.pack('>H', len(sni_list_length) + len(sni_entry)) + sni_list_length + sni_entry
    extensions = sni_ext
    extensions_length = struct.pack('>H', len(extensions))

    client_hello_body = (
        client_version + client_random +
        session_id_length + session_id +
        cipher_suites_length + cipher_suites +
        compression_methods_length + compression_methods +
        extensions_length + extensions
    )

    handshake_length = struct.pack('>I', len(client_hello_body))[1:]
    handshake_header = b'\x01' + handshake_length
    handshake_message = handshake_header + client_hello_body
    tls_record_length = struct.pack('>H', len(handshake_message))
    tls_record_header = b'\x16\x03\x01' + tls_record_length
    tls_record = tls_record_header + handshake_message

    return Raw(tls_record)


def create_packet(sni_name):
    eth = Ether(src="00:00:00:88:88:88", dst="00:11:22:33:44:55") / Dot1Q(vlan=100)
    ip = IP(src="10.0.0.1", dst="10.0.0.2")
    tcp = TCP(sport=12345, dport=443, flags="PA", seq=1000, ack=0)
    tls = create_tls_clienthello(sni_name)
    packet = eth / ip / tcp / tls
    return packet

def create_pcap(output_path):
    packet = create_packet()
    wrpcap(output_path, [packet])
    print("PCAP file 'send.pcap' created successfully")

if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)

    for idx, sni in enumerate(sni_list):
        filename = f"sni_{idx}.pcap"
        output_path = os.path.join(base_dir, filename)

        pkt = create_packet(sni)
        wrpcap(output_path, [pkt])

        if Raw in pkt:
            bin_name = f"sni_{idx}.bin"
            bin_path = os.path.join(base_dir, bin_name)
            with open(bin_path, "wb") as f:
                f.write(bytes(pkt[Raw].load))

        print(f"Created: {filename} with SNI = '{sni}'")

        if Dot1Q in pkt and IP in pkt and TCP in pkt and Raw in pkt:
            print("  VLAN ID:", pkt[Dot1Q].vlan)
            print("  Source IP:", pkt[IP].src)
            print("  Dest IP:", pkt[IP].dst)
            print("  TCP Sport:", pkt[TCP].sport)
            print("  TCP Dport:", pkt[TCP].dport)
            if sni.encode() in bytes(pkt[Raw].load):
                print("  SNI found:", sni)
        print("-" * 40)