# 🛡️ NetShield

### Real-Time Network Security Monitoring & Threat Detection

NetShield is a Python-based network security monitoring system that captures TCP traffic, detects suspicious connection activity, calculates threat severity, stores security alerts in SQLite, and visualizes the results through a Streamlit SOC dashboard.

---

## 🚀 Features

- 🔍 Real-time TCP packet monitoring
- 🧪 TCP SYN port-scan detection
- 🔄 Repeated TCP SYN anomaly detection
- ⚠️ Automated severity classification
- 💾 SQLite-based security alert storage
- 📊 Interactive Streamlit SOC dashboard
- 📈 Network activity visualization
- 🧪 Safe local testing pipeline
- 📝 Structured security alert records

---

## 🏗️ Architecture

```text
                    Network Traffic
                          │
                          ▼
                  ┌───────────────┐
                  │ Packet Capture│
                  │    Scapy      │
                  └───────┬───────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Detection Engine│
                 └────────┬────────┘
                          │
                ┌─────────┴─────────┐
                ▼                   ▼
        TCP SYN Port Scan     SYN Anomaly
          Detection            Detection
                │                   │
                └─────────┬─────────┘
                          ▼
                  ┌───────────────┐
                  │Severity Engine│
                  └───────┬───────┘
                          │
                 MEDIUM / HIGH /
                    CRITICAL
                          │
                          ▼
                  ┌───────────────┐
                  │  SQLite DB    │
                  │ Security Alerts│
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ Streamlit SOC  │
                  │   Dashboard    │
                  └───────────────┘
```

---

## 🔍 Detection Engines

NetShield uses two detection engines to identify suspicious TCP connection activity.

### 1. TCP SYN Port Scan Detection

NetShield monitors incoming TCP SYN packets and tracks the destination ports contacted by the same source IP.

**Threshold:** 5 unique ports

**Time Window:** 10 seconds

When the threshold is reached, NetShield generates a TCP SYN port-scan alert.

### 2. Repeated TCP SYN Detection

NetShield monitors repeated TCP SYN attempts from the same source IP to the same destination IP.

**Threshold:** 10 SYN attempts

**Time Window:** 10 seconds

When the threshold is reached, NetShield generates a suspicious TCP connection alert.

---

## ⚠️ Severity Engine

NetShield assigns severity based on the number of detected SYN attempts.

| SYN Attempts | Severity |
|---|---|
| 5–9 | MEDIUM |
| 10–19 | HIGH |
| 20+ | CRITICAL |

---

## 📊 SOC Dashboard

The Streamlit dashboard provides a centralized view of detected security activity.

It displays:

- Total security alerts
- Medium, High and Critical alerts
- Latest security alert
- Detection summary
- Security alert details
- Network activity visualization

---

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application |
| Scapy | Network packet capture and analysis |
| SQLite | Security alert storage |
| Streamlit | SOC dashboard |
| Pandas | Alert data processing |
| Plotly | Data visualization |
| Git | Version control |
| GitHub | Source-code hosting |

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/PriyaRG004/NetShield.git
cd NetShield
```

### 2. Create a virtual environment

On Windows:

```powershell
python -m venv venv
```

Activate the virtual environment:

```powershell
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

---

## ▶️ Running the Dashboard

Start the NetShield SOC dashboard:

```powershell
streamlit run dashboard.py
```

Open the local URL provided by Streamlit in your browser.

---

## 🧪 Safe Detection Test

NetShield includes a safe local testing pipeline that simulates TCP SYN activity.

Run:

```powershell
python test_live_pipeline.py
```

This verifies the detection, severity classification, and database storage pipeline.

---

## 📡 Live Network Monitoring

NetShield can capture live TCP traffic using Scapy.

Run:

```powershell
python capture.py
```

Press `CTRL+C` to stop monitoring.

---

## 🗄️ Database

NetShield uses SQLite to store detected security alerts.

Each alert can contain:

- Timestamp
- Alert type
- Severity
- Source IP
- Destination IP
- Unique ports
- SYN attempts
- Time window
- Detection method

The SQLite database file is excluded from Git using `.gitignore`.

---

## 🧪 Testing

The project includes tests for the database, detection engines, and complete security pipeline.

Test files include:

```text
test_database.py
test_pipeline.py
test_full_pipeline.py
test_live_detection.py
test_live_pipeline.py
test_logger.py
```

---

## 📁 Project Structure

```text
NetShield/
│
├── capture.py
├── connection_detector.py
├── connection_pipeline.py
├── dashboard.py
├── database.py
├── detection.py
├── interfaces.py
├── logger.py
├── packet_test.py
├── severity.py
│
├── test_database.py
├── test_full_pipeline.py
├── test_live_detection.py
├── test_live_pipeline.py
├── test_logger.py
├── test_pipeline.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🎯 Project Objective

NetShield is a cybersecurity project demonstrating:

- Network traffic monitoring
- TCP packet analysis
- TCP SYN-based threat detection
- Rule-based severity classification
- Security alert management
- SQLite-based alert storage
- SOC-style security visualization

---

## 👩‍💻 Author

**Priya R G**

GitHub: https://github.com/PriyaRG004