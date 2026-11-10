import psutil

print("=== IoT Network Monitor ===")

connections = psutil.net_connections(kind="inet")

for connection in connections:
    if connection.raddr:
        print(
            "Local:",
            connection.laddr,
            "Remote:",
            connection.raddr,
            "Status:",
            connection.status
        )
