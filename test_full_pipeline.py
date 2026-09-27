from datetime import datetime

from detection import detect_syn_scan
from severity import calculate_port_scan_severity
from database import create_database, insert_alert


print("NetShield Full Security Pipeline Test")
print("=" * 60)


# ----------------------------------------------------------
# Initialize database
# ----------------------------------------------------------

create_database()


# ----------------------------------------------------------
# Simulated inbound SYN scan
# ----------------------------------------------------------

source_ip = "192.168.0.50"
destination_ip = "192.168.0.101"

ports = [
    21,
    22,
    23,
    25,
    80
]


# ----------------------------------------------------------
# Process each simulated SYN
# ----------------------------------------------------------

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

        # Calculate severity
        severity = calculate_port_scan_severity(
            alert["unique_ports"]
        )

        # Add fields
        alert["severity"] = severity

        alert["timestamp"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        # Save
        insert_alert(alert)

        print()
        print("🚨 SECURITY ALERT 🚨")
        print(
            f"Unique ports: "
            f"{alert['unique_ports']}"
        )
        print(
            f"Severity: "
            f"{alert['severity']}"
        )
        print(
            f"Detection: "
            f"{alert['detection']}"
        )

        print()
        print(
            "✓ Alert saved to database."
        )


print()
print("=" * 60)
print("Pipeline test complete.")