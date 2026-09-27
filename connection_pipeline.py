from datetime import datetime

from database import create_database, insert_alert
from severity import calculate_syn_anomaly_severity

# ==========================================================
# CONFIGURATION
# ==========================================================

SOURCE_IP = "192.168.0.50"
DESTINATION_IP = "192.168.0.101"

TIME_WINDOW = 10

SYN_THRESHOLD = 10


# ==========================================================
# MAIN CONNECTION DETECTION PIPELINE
# ==========================================================

def run_connection_detection():

    print("NetShield TCP Connection Security Pipeline")
    print("=" * 60)

    print()
    print("Testing repeated TCP SYN attempts...")
    print()

    syn_attempts = 0

    # Make sure database exists
    create_database()

    # Simulate repeated SYN attempts
    for i in range(12):

        syn_attempts += 1

        print(
            f"{SOURCE_IP} -> {DESTINATION_IP} | "
            f"SYN attempts: {syn_attempts}"
        )

        # Detection threshold reached
        if syn_attempts == SYN_THRESHOLD:

            print()
            print("🚨 SECURITY ALERT 🚨")

            print(
                "Type: Suspicious TCP Connection Activity"
            )

            print(
                f"Source IP: {SOURCE_IP}"
            )

            print(
                f"Destination IP: {DESTINATION_IP}"
            )

            print(
                f"SYN attempts: {syn_attempts}"
            )

            print(
                f"Time window: {TIME_WINDOW} seconds"
            )

            print(
                "Detection: Repeated TCP SYN attempts"
            )

            # --------------------------------------------------
            # Calculate severity
            # --------------------------------------------------

            severity = calculate_syn_anomaly_severity(
    syn_attempts
)

            print(
                f"Severity: {severity}"
            )

            # --------------------------------------------------
            # Create alert
            # --------------------------------------------------

            alert = {

                "timestamp": datetime.now().isoformat(
                    timespec="seconds"
                ),

                "type":
                    "Suspicious TCP Connection Activity",

                "severity":
                    severity,

                "source_ip":
                    SOURCE_IP,

                "destination_ip":
                    DESTINATION_IP,

                "unique_ports":
                     None,
                "attempts":
                     syn_attempts,
                

                "time_window":
                    TIME_WINDOW,

                "detection":
                    "Repeated TCP SYN attempts"
            }

            # --------------------------------------------------
            # Save alert
            # --------------------------------------------------

            insert_alert(alert)

            print()
            print("✓ Alert saved to SQLite database.")
            print()

            # Stop after creating one alert
            break


# ==========================================================
# PROGRAM ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    run_connection_detection()