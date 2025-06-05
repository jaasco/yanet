from scapy.all import Ether, IP, TCP, Dot1Q, wrpcap, Raw
import struct  

def create_tls_clienthello(server_name: str = None):
    # TLS record + handshake headers (filled later)
    tls_record_header = b'\x16\x03\x01\x00\x00'
    handshake_header = b'\x01\x00\x00\x00'

    # ClientHello fields
    client_version = b'\x03\x03'
    client_random = b'\x00' * 32
    session_id_length = b'\x00'
    session_id = b''
    cipher_suites_length = b'\x00\x02'
    cipher_suites = b'\xC0\x2F'
    compression_methods_length = b'\x01'
    compression_methods = b'\x00'

    # Optional SNI extension
    if server_name:
        sni_bytes = server_name.encode("utf-8")
        server_name_length = struct.pack('>H', len(sni_bytes))
        sni_entry = b'\x00' + server_name_length + sni_bytes
        sni_list_length = struct.pack('>H', len(sni_entry))
        sni_ext = b'\x00\x00' + struct.pack('>H', len(sni_list_length) + len(sni_entry)) + sni_list_length + sni_entry
        extensions = sni_ext
    else:
        extensions = b''

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

# MAC
client_mac = "00:00:00:88:88:88"
lp_mac     = "00:11:22:33:44:55"
peer_mac   = "00:00:00:11:11:11"

# VLAN
vlan_in  = 100
vlan_out = 200

# IP
client_ip = "10.0.0.1"
server_ip = "10.0.0.2"

# TCP
sport = 12345
dport = 8443
seq = 1000

# SEND good
eth = Ether(src=client_mac, dst=lp_mac) / Dot1Q(vlan=vlan_in)
ip = IP(src=client_ip, dst=server_ip, ttl=64)
tcp = TCP(sport=sport, dport=dport, flags="PA", seq=seq)
tls = create_tls_clienthello("good.example.com")
send_pkt = eth / ip / tcp / tls
wrpcap("send-001.pcap", [send_pkt])

# RECV good
recv_pkt = eth / ip / tcp / tls
wrpcap("recv-001.pcap", [recv_pkt])

# SEND bad
eth = Ether(src=client_mac, dst=lp_mac) / Dot1Q(vlan=vlan_in)
ip = IP(src=client_ip, dst=server_ip, ttl=64)
tcp = TCP(sport=sport, dport=dport, flags="PA", seq=seq)
tls = create_tls_clienthello("bad.example.com")
send_pkt = eth / ip / tcp / tls
wrpcap("send-002.pcap", [send_pkt])

# RECV bad
wrpcap("recv-002.pcap", [])