\# 🛡️ NetShield



\## Network Security Monitoring \& Threat Detection Platform



NetShield is a Python-based network security monitoring platform that captures TCP traffic, detects suspicious connection patterns, classifies the severity of detected activity, stores security alerts in SQLite, and presents the results through an interactive Streamlit dashboard.



\## 🚀 Features



\- Live TCP packet monitoring using Scapy

\- TCP SYN port scan detection

\- Repeated TCP SYN connection anomaly detection

\- Configurable detection thresholds and time windows

\- Security severity classification

\- SQLite-based alert storage

\- Security alert dashboard

\- Network activity visualization

\- Automated pipeline testing



\## 🔍 Detection Engines



\### 1. TCP SYN Port Scan Detection



NetShield monitors TCP SYN packets and tracks unique destination ports.



Detection threshold:



\- 5–9 ports → MEDIUM

\- 10–19 ports → HIGH

\- 20+ ports → CRITICAL



\### 2. Repeated TCP SYN Detection



NetShield also monitors repeated SYN connection attempts from the same source.



Detection threshold:



\- 10 SYN attempts → HIGH

\- 20+ SYN attempts → CRITICAL



A rolling time window is used to analyze recent connection activity.



\## 🏗️ Architecture



```text

Network Traffic

&#x20;     ↓

Scapy Packet Capture

&#x20;     ↓

Packet Processing

&#x20;     ↓

Detection Engines

&#x20;  ↙          ↘

Port Scan    SYN Anomaly

Detection    Detection

&#x20;  ↓             ↓

&#x20;     Severity Engine

&#x20;            ↓

&#x20;      SQLite Database

&#x20;            ↓

&#x20;    Streamlit Dashboard

