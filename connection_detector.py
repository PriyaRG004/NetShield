from collections import defaultdict
from datetime import datetime, timedelta


# ==========================================================
# CONFIGURATION
# ==========================================================

ATTEMPT_THRESHOLD = 10
TIME_WINDOW = 10


# ==========================================================
# STORAGE
# ==========================================================

connection_attempts = defaultdict(list)

alerted_sources = {}


# ==========================================================
# DETECTION FUNCTION
# ==========================================================

def detect_connection_anomaly(
    source_ip,
    destination_ip,
    tcp_flags
):

    current_time = datetime.now()

    # ------------------------------------------------------
    # Only investigate initial SYN packets
    # ------------------------------------------------------

    if tcp_flags != "S":
        return None


    # ------------------------------------------------------
    # Store SYN attempt
    # ------------------------------------------------------

    connection_attempts[source_ip].append(
        (
            current_time,
            destination_ip
        )
    )


    # ------------------------------------------------------
    # Remove old attempts
    # ------------------------------------------------------

    cutoff_time = (
        current_time -
        timedelta(seconds=TIME_WINDOW)
    )

    connection_attempts[source_ip] = [
        attempt
        for attempt in connection_attempts[source_ip]
        if attempt[0] >= cutoff_time
    ]


    # ------------------------------------------------------
    # Count recent attempts
    # ------------------------------------------------------

    attempt_count = len(
        connection_attempts[source_ip]
    )


    print(
        f"{source_ip} -> {destination_ip} "
        f"| SYN attempts: {attempt_count}"
    )


    # ------------------------------------------------------
    # Check threshold
    # ------------------------------------------------------

    if attempt_count < ATTEMPT_THRESHOLD:
        return None


    # ------------------------------------------------------
    # Alert suppression
    # ------------------------------------------------------

    previous_alert = alerted_sources.get(
        source_ip
    )

    if previous_alert is not None:

        if (
            current_time - previous_alert
        ).total_seconds() < TIME_WINDOW:

            return None


    # ------------------------------------------------------
    # Record that an alert was generated
    # ------------------------------------------------------

    alerted_sources[source_ip] = current_time


    # ------------------------------------------------------
    # Create security alert
    # ------------------------------------------------------

    return {
        "type": "Suspicious TCP Connection Activity",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "attempts": attempt_count,
        "time_window": TIME_WINDOW,
        "detection": "Repeated TCP SYN attempts"
    }


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    print(
        "NetShield TCP Connection Anomaly Detector"
    )

    print("-" * 55)

    print()
    print(
        "Testing repeated TCP SYN attempts..."
    )

    print()


    source_ip = "192.168.0.50"

    destination_ip = "192.168.0.101"


    for i in range(12):

        alert = detect_connection_anomaly(
            source_ip,
            destination_ip,
            "S"
        )


        if alert:

            print()

            print(
                "🚨 SECURITY ALERT 🚨"
            )

            print(
                f"Type: {alert['type']}"
            )

            print(
                f"Source IP: "
                f"{alert['source_ip']}"
            )

            print(
                f"Destination IP: "
                f"{alert['destination_ip']}"
            )

            print(
                f"SYN attempts: "
                f"{alert['attempts']}"
            )

            print(
                f"Time window: "
                f"{alert['time_window']} seconds"
            )

            print(
                f"Detection: "
                f"{alert['detection']}"
            )