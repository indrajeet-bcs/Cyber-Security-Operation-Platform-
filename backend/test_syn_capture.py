from scapy.all import sniff, TCP, IP

print("Starting TCP SYN packet capture...")
print("Generate traffic to port 8080 now...")

def packet_callback(packet):
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        # SYN flag set and ACK flag not set
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):

            if packet.haslayer(IP):
                print(
                    f"TCP SYN detected: "
                    f"{packet[IP].src} -> "
                    f"{packet[IP].dst}:{tcp.dport}"
                )

sniff(
    filter="tcp",
    prn=packet_callback,
    store=False
)