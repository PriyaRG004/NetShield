from logger import log_alert


test_alert = {
    "type": "Possible Port Scan",
    "source_ip": "192.168.0.50",
    "destination_ip": "192.168.0.101",
    "unique_ports": 5,
    "time_window": 10,
    "detection": "TCP SYN scan",
    "severity": "HIGH"
}


log_alert(test_alert)

print("Test alert created successfully.")