from scapy.all import sniff, IP, TCP, UDP


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n=== Packet Captured ===")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        # TCP packets
        if TCP in packet:
            print("Layer          : TCP")
            payload = bytes(packet[TCP].payload)
            if payload:
                print(f"Payload (bytes): {payload[:50]}")
            else:
                print("Payload        : None")

        # UDP packets
        elif UDP in packet:
            print("Layer          : UDP")
            payload = bytes(packet[UDP].payload)
