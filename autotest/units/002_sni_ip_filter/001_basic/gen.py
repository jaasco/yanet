#!/usr/bin/env python3
from scapy.all import *
import os
import struct

def write_pcap(filename, *packetsList):
    if len(packetsList) == 0:
        PcapWriter(filename, linktype=1).close()
        return

    for packets in packetsList:
        if isinstance(packets, list):
            for packet in packets:
                packet.time = 0
                wrpcap(filename, [packet], append=True)
        else:
            packets.time = 0
            wrpcap(filename, [packets], append=True)

def create_tls_clienthello(server_name: str):
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

    sni_bytes = server_name.encode("utf-8")
    server_name_length = struct.pack('>H', len(sni_bytes))
    sni_entry = b'\x00' + server_name_length + sni_bytes
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

def create_packet(sni: str):
    eth = Ether(src="00:00:00:88:88:88", dst="00:11:22:33:44:55") / Dot1Q(vlan=100)
    ip = IP(src="10.0.0.1", dst="10.0.0.2")
    tcp = TCP(sport=12345, dport=443, flags="PA", seq=1000, ack=0)
    tls = create_tls_clienthello(sni)
    return eth / ip / tcp / tls

write_pcap("send-001.pcap", [create_packet('bad.example.com')])
write_pcap("recv-001.pcap")

write_pcap("send-002.pcap", [create_packet('good.example.com')])
write_pcap("recv-002.pcap", [create_packet('good.example.com')])
