# ==========================================================
# NETSHIELD SEVERITY ENGINE
# ==========================================================


def calculate_port_scan_severity(unique_ports):
    """
    Calculate severity for a TCP SYN port scan
    based on the number of unique destination ports.
    """

    if unique_ports >= 20:
        return "CRITICAL"

    elif unique_ports >= 10:
        return "HIGH"

    elif unique_ports >= 5:
        return "MEDIUM"

    return "LOW"


def calculate_syn_anomaly_severity(syn_attempts):
    """
    Calculate severity for repeated TCP SYN attempts.
    """

    if syn_attempts >= 20:
        return "CRITICAL"

    elif syn_attempts >= 10:
        return "HIGH"

    return "LOW"


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    print("NetShield Severity Engine")
    print("-" * 50)

    print()
    print("Port Scan Severity")
    print("-" * 30)

    port_values = [
        3,
        5,
        8,
        10,
        15,
        20,
        25
    ]

    for ports in port_values:

        severity = calculate_port_scan_severity(
            ports
        )

        print(
            f"Unique ports: {ports} "
            f"-> Severity: {severity}"
        )


    print()
    print("SYN Anomaly Severity")
    print("-" * 30)

    syn_values = [
        5,
        9,
        10,
        15,
        19,
        20,
        30
    ]

    for attempts in syn_values:

        severity = calculate_syn_anomaly_severity(
            attempts
        )

        print(
            f"SYN attempts: {attempts} "
            f"-> Severity: {severity}"
        )