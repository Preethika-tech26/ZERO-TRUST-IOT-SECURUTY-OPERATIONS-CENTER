from scapy.all import sniff

packet_count = 0

def packet_received(packet):
    global packet_count
    packet_count += 1
    print("Packet received:", packet_count)

print("=== IoT Network Packet Capture ===")
print("Capturing packets...")

sniff(prn=packet_received, count=20)

print("Total packets:", packet_count)