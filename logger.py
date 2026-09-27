import json
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("alerts.json")


def log_alert(alert):
    """
    Save a security alert to alerts.json.
    """

    # Add the current timestamp
    alert["timestamp"] = datetime.now().isoformat(
        timespec="seconds"
    )

    # Read existing alerts
    if LOG_FILE.exists():

        try:
            with open(LOG_FILE, "r") as file:
                alerts = json.load(file)

        except json.JSONDecodeError:
            alerts = []

    else:
        alerts = []

    # Add the new alert
    alerts.append(alert)

    # Save everything back to the file
    with open(LOG_FILE, "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )

    print("📝 Alert saved to alerts.json")