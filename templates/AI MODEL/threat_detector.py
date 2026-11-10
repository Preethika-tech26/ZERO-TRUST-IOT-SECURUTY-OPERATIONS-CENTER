def detect_threat(packet_count, connection_count):

    if packet_count > 100 or connection_count > 20:
        return "THREAT DETECTED"
    else:
        return "NORMAL"


print("=== IoT AI Threat Detection ===")

packet_count = int(input("Enter packet count: "))
connection_count = int(input("Enter connection count: "))

result = detect_threat(packet_count, connection_count)

print("Network Status:", result)

if result == "THREAT DETECTED":
    print("⚠ ALERT: Suspicious network activity detected!")
else:
    print("✓ Network traffic is normal.")