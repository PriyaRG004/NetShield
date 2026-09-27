from scapy.all import IP, TCP

packet = IP(
    src="192.168.1.10",
    dst="192.168.1.20"
) / TCP(
    sport=52341,
    dport=443
)

print("Source IP:", packet[IP].src)
print("Destination IP:", packet[IP].dst)
print("Source Port:", packet[TCP].sport)
print("Destination Port:", packet[TCP].dport)