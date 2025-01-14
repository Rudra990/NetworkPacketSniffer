from scapy.all import sniff

def simple_callback(packet):
    print(packet.summary())

# Capture a single packet (for testing purposes)
sniff(count=1, prn=simple_callback)
