# 🔐 SOC Log Analyzer - Brute Force Detection Tool

## 📌 Overview
This project is a simple Security Operations Center (SOC) tool built using Python and Linux.  
It analyzes SSH authentication logs and detects potential brute force attacks based on failed login attempts.

---

## ⚙️ Features
- Reads SSH logs using `journalctl`
- Detects failed login attempts
- Extracts attacker IP addresses using regex
- Tracks failed attempts per IP
- Generates alerts for brute force detection

---

## 🧠 How It Works
1. Collects SSH logs from Linux system
2. Splits logs into individual events
3. Filters failed login attempts
4. Extracts IP addresses
5. Counts repeated failures per IP
6. Triggers alert if threshold (≥5) is reached

---

## 🛠️ Technologies Used
- Python 3
- Linux (Kali)
- journalctl
- Regex (re module)

---

## 🚨 Detection Logic
If an IP address shows **5 or more failed login attempts**, it is flagged as a possible brute force attack.

---

## 📂 Project Structure
SOC-Log-Analyzer/
├── core/
│ ├── analyzer.py # Log parsing and analysis logic
│ ├── detector.py # Brute-force detection engine
│ ├── report.py # Report generation module
│ └── pycache/ # Python cache files (ignored in production)
│
├── logs/
│ └── auth.log # Sample authentication log file
│
├── reports/
│ └── alert_report.txt # Generated security report
│
├── main.py # Entry point of the application
└── README.md

