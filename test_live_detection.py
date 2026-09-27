from detection import detect_syn_scan


print("NetShield Live Detection Test")
print("=" * 60)


source_ip = "192.168.0.50"
destination_ip = "192.168.0.101"

ports = [
    21,
    22,
    23,
    25,
    80
]


for port in ports:

    alert = detect_syn_scan(
        source_ip,
        destination_ip,
        port
    )

    print(
        f"{source_ip} -> "
        f"{destination_ip}:{port}"
    )

    if alert:

        print()
        print("🚨 SECURITY ALERT 🚨")
        print(
            f"Unique ports: "
            f"{alert['unique_ports']}"
        )
        print(
            f"Detection: "
            f"{alert['detection']}"
        )