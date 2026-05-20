from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        print("\n========== PACKET ==========")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp.sport}")
            print(f"Destination Port: {udp.dport}")

sniff(filter="ip", prn=packet_callback, store=False)

