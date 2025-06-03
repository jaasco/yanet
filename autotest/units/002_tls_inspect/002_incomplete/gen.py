from scapy.all import Ether, IP, TCP, Dot1Q, wrpcap

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
dport = 443
seq = 1000

# SEND (SYN from client)
send_pkt = Ether(src=client_mac, dst=lp_mac) / Dot1Q(vlan=vlan_in) / \
           IP(src=client_ip, dst=server_ip, ttl=64) / \
           TCP(sport=sport, dport=dport, flags="S", seq=seq)

wrpcap("send-001.pcap", [send_pkt])

# RECV 
recv_pkt = Ether(src=lp_mac, dst=peer_mac) / Dot1Q(vlan=vlan_out) / \
           IP(src=client_ip, dst=server_ip, ttl=63) / \
           TCP(sport=sport, dport=dport, flags="S", seq=seq)

wrpcap("recv-001.pcap", [recv_pkt])
