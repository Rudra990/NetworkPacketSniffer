##installed npcap and scapy

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

# List available interfaces for debugging
print("Available Network Interfaces:")
print(get_if_list())

def packet_callback(packet):
    # Print the packet summary for debugging
    print(f"Captured Packet: {packet.summary()}")

    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"IP Packet: {src_ip} -> {dst_ip}")

        # Check if the packet is a TCP packet
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            if packet[TCP].payload:
                print(f"Data: {packet[TCP].payload}")

        # Check if the packet is a UDP packet
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            if packet[UDP].payload:
                print(f"Data: {packet[UDP].payload}")

        # Check if the packet is an ICMP packet
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Packet: Type={icmp_type}, Code={icmp_code}")

# Specify the interface name here based on the output from get_if_list()
selected_iface = "\\Device\\NPF_Loopback"
# Change this to the correct interface
print(f"Starting packet capture on interface: {selected_iface}. Press Ctrl+C to stop.")
sniff(iface=selected_iface, prn=packet_callback, store=0)

print("Packet capture complete.")


