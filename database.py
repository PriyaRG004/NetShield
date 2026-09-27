import sqlite3
from pathlib import Path


DATABASE_FILE = Path("netshield.db")


def create_database():
    """
    Create the NetShield database and alerts table
    if they do not already exist.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            unique_ports INTEGER,
            attempts INTEGER,
            time_window INTEGER,
            detection TEXT
        )
    """)

    connection.commit()

    connection.close()


def insert_alert(alert):
    """
    Insert one security alert into the database.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            severity,
            source_ip,
            destination_ip,
            unique_ports,
            attempts,
            time_window,
            detection
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["type"],
        alert["severity"],
        alert["source_ip"],
        alert["destination_ip"],
        alert.get("unique_ports"),
        alert.get("attempts"),
        alert["time_window"],
        alert["detection"]
    ))

    connection.commit()

    connection.close()


def get_all_alerts():
    """
    Retrieve all stored security alerts.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            severity,
            source_ip,
            destination_ip,
            unique_ports,
            attempts,
            time_window,
            detection
        FROM alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


if __name__ == "__main__":

    create_database()

    print("NetShield database created successfully.")
    print("Database file:", DATABASE_FILE)