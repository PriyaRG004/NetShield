from database import create_database, insert_alert, get_all_alerts
from datetime import datetime


# Create database
create_database()


# Create a test security alert
test_alert = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "type": "Possible Port Scan",
    "severity": "MEDIUM",
    "source_ip": "192.168.0.50",
    "destination_ip": "192.168.0.101",
    "unique_ports": 5,
    "time_window": 10,
    "detection": "TCP SYN scan"
}


# Insert alert
insert_alert(test_alert)

print("Alert inserted successfully.")


# Retrieve alerts
alerts = get_all_alerts()

print()
print("Stored alerts:")
print("-" * 60)

for alert in alerts:
    print(alert)