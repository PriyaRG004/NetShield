from scapy.all import sniff, IP, TCP
import socket
from datetime import datetime

from detection import detect_syn_scan
from connection_detector import detect_connection_anomaly

from severity import (
    calculate_port_scan_severity,
    calculate_syn_anomaly_severity
)

from database import (
    create_database,
    insert_alert
)


# ==========================================================
# CONFIGURATION
# ==========================================================

CAPTURE_COUNT = 0


# ==========================================================
# INITIALIZE DATABASE
# ==========================================================

create_database()


# ==========================================================
# GET LOCAL IP
# ==========================================================

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)


# ==========================================================
# PACKET PROCESSING
# ==========================================================

def process_packet(packet):

    # ------------------------------------------------------
    # Make sure packet has IP + TCP
    # ------------------------------------------------------

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return


    # ------------------------------------------------------
    # Extract packet information
    # ------------------------------------------------------

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport

    flags = packet[TCP].flags


    # ------------------------------------------------------
    # Display packet
    # ------------------------------------------------------

    print()
    print("--- Packet Captured ---")

    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print("Protocol: TCP")
    print(f"Source Port: {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"TCP Flags: {flags}")


    # ======================================================
    # ONLY PROCESS INBOUND INITIAL SYN PACKETS
    # ======================================================

    if destination_ip != local_ip:
        return

    if "S" not in flags:
        return

    if "A" in flags:
        return


    # ======================================================
    # DETECTION 1 — TCP SYN PORT SCAN
    # ======================================================

    port_scan_alert = detect_syn_scan(
        source_ip,
        destination_ip,
        destination_port
    )


    if port_scan_alert is not None:

        # --------------------------------------------------
        # Calculate severity
        # --------------------------------------------------

        severity = calculate_port_scan_severity(
            port_scan_alert["unique_ports"]
        )

        port_scan_alert["severity"] = severity

        port_scan_alert["timestamp"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        # SYN port scan does not use the attempts field
        port_scan_alert["attempts"] = None


        # --------------------------------------------------
        # Display alert
        # --------------------------------------------------

        print()
        print("🚨 SECURITY ALERT 🚨")

        print(
            f"Type: "
            f"{port_scan_alert['type']}"
        )

        print(
            f"Source IP: "
            f"{port_scan_alert['source_ip']}"
        )

        print(
            f"Destination IP: "
            f"{port_scan_alert['destination_ip']}"
        )

        print(
            f"Unique ports: "
            f"{port_scan_alert['unique_ports']}"
        )

        print(
            f"Time window: "
            f"{port_scan_alert['time_window']} seconds"
        )

        print(
            f"Detection: "
            f"{port_scan_alert['detection']}"
        )

        print(
            f"Severity: "
            f"{port_scan_alert['severity']}"
        )


        # --------------------------------------------------
        # Save alert
        # --------------------------------------------------

        insert_alert(port_scan_alert)

        print("✓ Port scan alert saved to database.")


    # ======================================================
    # DETECTION 2 — REPEATED TCP SYN ATTEMPTS
    # ======================================================

    connection_alert = detect_connection_anomaly(
        source_ip,
        destination_ip,
        flags
    )


    if connection_alert is None:
        return


    # ======================================================
    # CALCULATE SEVERITY
    # ======================================================

    severity = calculate_syn_anomaly_severity(
        connection_alert["attempts"]
    )


    connection_alert["severity"] = severity

    connection_alert["timestamp"] = (
        datetime.now().isoformat(
            timespec="seconds"
        )
    )


    # ======================================================
    # DATABASE FIELDS
    # ======================================================

    # This alert is NOT a port scan.
    # Therefore unique_ports should be NULL.

    connection_alert["unique_ports"] = None

    # Store the actual SYN attempt count
    connection_alert["attempts"] = (
        connection_alert["attempts"]
    )


    # ======================================================
    # DISPLAY SECURITY ALERT
    # ======================================================

    print()
    print("🚨 SECURITY ALERT 🚨")

    print(
        f"Type: "
        f"{connection_alert['type']}"
    )

    print(
        f"Source IP: "
        f"{connection_alert['source_ip']}"
    )

    print(
        f"Destination IP: "
        f"{connection_alert['destination_ip']}"
    )

    print(
        f"SYN attempts: "
        f"{connection_alert['attempts']}"
    )

    print(
        f"Time window: "
        f"{connection_alert['time_window']} seconds"
    )

    print(
        f"Detection: "
        f"{connection_alert['detection']}"
    )

    print(
        f"Severity: "
        f"{connection_alert['severity']}"
    )


    # ======================================================
    # SAVE ALERT TO DATABASE
    # ======================================================

    insert_alert(connection_alert)

    print("✓ SYN anomaly alert saved to database.")


# ==========================================================
# START NETSHIELD
# ==========================================================

print("=" * 60)
print("       NETSHIELD LIVE NETWORK MONITOR")
print("=" * 60)

print()
print(f"Local IP: {local_ip}")

print()
print("Detection Engines:")

print("  1. TCP SYN Port Scan Detection")
print("     Threshold: 5 unique ports")
print("     Time Window: 10 seconds")

print()

print("  2. Repeated TCP SYN Detection")
print("     Threshold: 10 SYN attempts")
print("     Time Window: 10 seconds")

print()

print("Severity Engine:")
print("  5-9  → MEDIUM")
print("  10-19 → HIGH")
print("  20+ → CRITICAL")

print()
print("Starting live packet capture...")
print("Press CTRL+C to stop.")
print()


# ==========================================================
# START PACKET CAPTURE
# ==========================================================

try:

    sniff(
        iface="Wi-Fi",
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    print()
    print("=" * 60)
    print("NetShield monitoring stopped.")
    print("=" * 60)