from datetime import datetime

from detection import detect_syn_scan
from connection_detector import detect_connection_anomaly
from severity import calculate_port_scan_severity
from database import create_database, insert_alert


# ==========================================================
# CONFIGURATION
# ==========================================================

SOURCE_IP = "127.0.0.1"
DESTINATION_IP = "127.0.0.1"

TIME_WINDOW = 10


# ==========================================================
# INITIALIZE DATABASE
# ==========================================================

create_database()


print("=" * 60)
print("NETSHIELD SAFE LIVE PIPELINE TEST")
print("=" * 60)

print()
print("Simulating inbound TCP SYN packets locally...")
print()


# ==========================================================
# SIMULATE TCP SYN PACKETS
# ==========================================================

ports = [21, 22, 23, 25, 80]


for destination_port in ports:

    print(
        f"{SOURCE_IP} -> "
        f"{DESTINATION_IP}:"
        f"{destination_port}"
    )

    # ------------------------------------------------------
    # PORT SCAN DETECTOR
    # ------------------------------------------------------

    port_scan_alert = detect_syn_scan(
        SOURCE_IP,
        DESTINATION_IP,
        destination_port
    )


    # ------------------------------------------------------
    # REPEATED SYN DETECTOR
    # ------------------------------------------------------

    connection_alert = detect_connection_anomaly(
        SOURCE_IP,
        DESTINATION_IP,
        "S"
    )


    # ------------------------------------------------------
    # PORT SCAN ALERT
    # ------------------------------------------------------

    if port_scan_alert is not None:

        severity = calculate_port_scan_severity(
            port_scan_alert["unique_ports"]
        )

        port_scan_alert["severity"] = severity

        port_scan_alert["timestamp"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        insert_alert(port_scan_alert)

        print()
        print("🚨 PORT SCAN DETECTED")

        print(
            f"Unique ports: "
            f"{port_scan_alert['unique_ports']}"
        )

        print(
            f"Severity: {severity}"
        )

        print(
            "✓ Port scan alert saved."
        )


    # ------------------------------------------------------
    # CONNECTION ANOMALY ALERT
    # ------------------------------------------------------

    if connection_alert is not None:

        severity = calculate_port_scan_severity(
            connection_alert["attempts"]
        )

        connection_alert["severity"] = severity

        connection_alert["timestamp"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        connection_alert["unique_ports"] = (
            connection_alert["attempts"]
        )

        insert_alert(connection_alert)

        print()
        print("🚨 SYN ANOMALY DETECTED")

        print(
            f"SYN attempts: "
            f"{connection_alert['attempts']}"
        )

        print(
            f"Severity: {severity}"
        )

        print(
            "✓ SYN anomaly alert saved."
        )


print()
print("=" * 60)
print("SAFE PIPELINE TEST COMPLETE")
print("=" * 60)