from scapy.all import Ether, IP, TCP, UDP, ICMP, Dot1Q, wrpcap

# MACs
client_mac = "00:00:00:88:88:88"
lp_mac     = "00:11:22:33:44:55"
peer_mac   = "00:00:00:11:11:11"

# VLAN
vlan_in  = 100
vlan_out = 200

# IP
client_ip = "10.0.0.1"
server_ip = "10.0.0.2"

# Ports
sport = 12345
dport = 443
seq = 1000

# -------------------------------
# 1. UDP packet (with VLAN)
# -------------------------------

send_udp = Ether(src=client_mac, dst=lp_mac) / Dot1Q(vlan=vlan_in) / \
           IP(src=client_ip, dst=server_ip, ttl=64) / \
           UDP(sport=sport, dport=dport) / b"hello"

recv_udp = Ether(src=lp_mac, dst=peer_mac) / Dot1Q(vlan=vlan_out) / \
           IP(src=client_ip, dst=server_ip, ttl=63) / \
           UDP(sport=sport, dport=dport) / b"hello"

wrpcap("send-001.pcap", [send_udp])
wrpcap("recv-001.pcap", [recv_udp])

# -------------------------------
# 2. ICMP packet (with VLAN)
# -------------------------------

send_icmp = Ether(src=client_mac, dst=lp_mac) / Dot1Q(vlan=vlan_in) / \
            IP(src=client_ip, dst=server_ip, ttl=64) / \
            ICMP(type="echo-request") / b"ping"

recv_icmp = Ether(src=lp_mac, dst=peer_mac) / Dot1Q(vlan=vlan_out) / \
            IP(src=client_ip, dst=server_ip, ttl=63) / \
            ICMP(type="echo-request") / b"ping"

del recv_icmp[IP].chksum
del recv_icmp[ICMP].chksum
recv_icmp = recv_icmp.__class__(bytes(recv_icmp))

wrpcap("send-002.pcap", [send_icmp])
wrpcap("recv-002.pcap", [recv_icmp])

# -------------------------------
# 3. TCP packet without VLAN
# -------------------------------

send_tcp_plain = Ether(src=client_mac, dst=lp_mac) / \
                 IP(src=client_ip, dst=server_ip, ttl=64) / \
                 TCP(sport=sport, dport=dport, flags="S", seq=seq)

recv_tcp_plain = Ether(dst=lp_mac, src=client_mac) / \
                 IP(src=client_ip, dst=server_ip, ttl=64) / \
                 TCP(sport=sport, dport=dport, flags="S", seq=seq)

wrpcap("send-003.pcap", [send_tcp_plain])
wrpcap("recv-003.pcap", [recv_tcp_plain])
