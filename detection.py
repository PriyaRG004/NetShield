from collections import defaultdict
from datetime import datetime, timedelta


# ==========================================================
# CONFIGURATION
# ==========================================================

PORT_THRESHOLD = 5
TIME_WINDOW = 10


# ==========================================================
# TRACKING
# ==========================================================

scan_tracker = defaultdict(list)


# ==========================================================
# DETECTION FUNCTION
# ==========================================================

def detect_syn_scan(
    source_ip,
    destination_ip,
    destination_port
):

    current_time = datetime.now()

    key = (
        source_ip,
        destination_ip
    )

    # ------------------------------------------------------
    # Add current connection attempt
    # ------------------------------------------------------

    scan_tracker[key].append(
        (
            current_time,
            destination_port
        )
    )


    # ------------------------------------------------------
    # Remove old events
    # ------------------------------------------------------

    cutoff_time = (
        current_time -
        timedelta(seconds=TIME_WINDOW)
    )

    scan_tracker[key] = [
        event
        for event in scan_tracker[key]
        if event[0] >= cutoff_time
    ]


    # ------------------------------------------------------
    # Get unique destination ports
    # ------------------------------------------------------

    unique_ports = set()

    for event in scan_tracker[key]:

        unique_ports.add(
            event[1]
        )


    port_count = len(unique_ports)


    # ------------------------------------------------------
    # Detect possible scan
    # ------------------------------------------------------

    if port_count >= PORT_THRESHOLD:

        return {
            "type": "Possible Port Scan",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "unique_ports": port_count,
            "time_window": TIME_WINDOW,
            "detection": "TCP SYN scan"
        }


    return None