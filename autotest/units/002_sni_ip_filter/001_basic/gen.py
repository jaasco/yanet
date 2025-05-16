#!/usr/bin/env python3
from scapy.all import Ether, Dot1Q, IP, TCP, Raw, wrpcap, rdpcap
import os
import struct

def create_tls_clienthello():
    # TLS Record Header (Content Type: Handshake (22), Version: TLS 1.0, Length: will be filled later)
    tls_record_header = b'\x16\x03\x01\x00\x00'
    
    # TLS Handshake Header (Handshake Type: ClientHello (1), Length: will be filled later)
    handshake_header = b'\x01\x00\x00\x00'
    
    # ClientHello Version (TLS 1.2)
    client_version = b'\x03\x03'
    
    # ClientHello Random (32 bytes)
    client_random = os.urandom(32)
    
    # Session ID (empty)
    session_id_length = b'\x00'
    session_id = b''
    
    # Cipher Suites (only TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F)
    cipher_suites_length = b'\x00\x02'
    cipher_suites = b'\xC0\x2F'
    
    # Compression Methods (only NULL compression)
    compression_methods_length = b'\x01'
    compression_methods = b'\x00'
    
    # SNI Extension (server_name)
    server_name = b'bad.example.com'
    server_name_length = struct.pack('>H', len(server_name))
    
    # SNI list (only one element: type 0 (hostname), length, name)
    sni_entry = b'\x00' + server_name_length + server_name
    sni_list_length = struct.pack('>H', len(sni_entry))
    
    # SNI Extension structure
    sni_ext = b'\x00\x00' + struct.pack('>H', len(sni_list_length) + len(sni_entry)) + sni_list_length + sni_entry
    
    # Collect all extensions
    extensions = sni_ext
    extensions_length = struct.pack('>H', len(extensions))
    
    # Assemble the entire ClientHello
    client_hello_body = (
        client_version + client_random +
        session_id_length + session_id +
        cipher_suites_length + cipher_suites +
        compression_methods_length + compression_methods +
        extensions_length + extensions
    )
    
    # Update length in Handshake header
    handshake_length = struct.pack('>I', len(client_hello_body))[1:]  # Remove first byte (only 3 bytes needed)
    handshake_header = b'\x01' + handshake_length
    
    # Assemble the entire Handshake packet
    handshake_message = handshake_header + client_hello_body
    
    # Update length in TLS Record header
    tls_record_length = struct.pack('>H', len(handshake_message))
    tls_record_header = b'\x16\x03\x01' + tls_record_length
    
    # Assemble the entire TLS Record
    tls_record = tls_record_header + handshake_message
    
    return Raw(tls_record)

def create_packet():
    eth = Ether(src="00:00:00:88:88:88", dst="00:11:22:33:44:55") / Dot1Q(vlan=100)
    ip = IP(src="10.0.0.1", dst="10.0.0.2")
    tcp = TCP(sport=12345, dport=443, flags="PA", seq=1000, ack=0)
    tls = create_tls_clienthello()
    packet = eth / ip / tcp / tls
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
            if b"bad.example.com" in bytes(pkt[Raw].load):
                print("SNI found: bad.example.com")
            print("-" * 40)