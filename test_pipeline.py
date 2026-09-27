from datetime import datetime

from detection import PortScanDetector
from severity import calculate_port_scan_severity
from database import create_database, insert_alert, get_all_alerts


# ==========================================================
# CONFIGURATION
# ==========================================================

LOCAL_IP = "192.168.0.101"


# ==========================================================
# INITIALIZE DATABASE
# ==========================================================

create_database()


# ==========================================================
# CREATE DETECTOR
# ==========================================================

detector = PortScanDetector(
    local_ip=LOCAL_IP,
    threshold=5,
    time_window=10
)


# ==========================================================
# SIMULATED PORT SCAN
# ==========================================================

source_ip = "192.168.0.50"

ports = [21, 22, 23, 25, 80]


print("NetShield Integration Test")
print("=" * 60)

for port in ports:

    result = detector.analyze(
        source_ip=source_ip,
        destination_ip=LOCAL_IP,
        destination_port=port,
        tcp_flags="S"
    )

    print(
        f"{source_ip} -> "
        f"{LOCAL_IP}:{port} | "
        f"Unique ports: {result['unique_ports']}"
    )


# ==========================================================
# CHECK DETECTION RESULT
# ==========================================================

if result["alert"]:

    print()
    print("🚨 Port scan detected!")
    print()

    # Calculate severity
    severity = calculate_port_scan_severity(
        result["unique_ports"]
    )

    print("Severity:", severity)

    # ======================================================
    # CREATE SECURITY EVENT
    # ======================================================

    alert = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "type": result["type"],
        "severity": severity,
        "source_ip": result["source_ip"],
        "destination_ip": result["destination_ip"],
        "unique_ports": result["unique_ports"],
        "time_window": result["time_window"],
        "detection": "TCP SYN scan"
    }

    # ======================================================
    # SAVE TO DATABASE
    # ======================================================

    insert_alert(alert)

    print()
    print("✓ Alert inserted into SQLite database.")


# ==========================================================
# READ DATABASE
# ==========================================================

print()
print("=" * 60)
print("Stored alerts")
print("=" * 60)

alerts = get_all_alerts()

for alert in alerts:

    print(alert)