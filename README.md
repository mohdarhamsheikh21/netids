# NetIDS — Network Packet Analyzer & Intrusion Detection System

A Blue Team cybersecurity tool built in Python using Scapy.
Monitors live network traffic and detects attacks in real time.

## What It Detects
- SYN Flood — detects DoS attacks via half-open TCP connections
- Port Scan — detects reconnaissance (like Nmap scans)
- Brute Force — detects repeated login attempts on SSH, RDP, FTP, MySQL
- ICMP Flood — detects ping flood attacks
- UDP Flood — detects UDP-based DoS attacks
- ARP Spoofing — detects Man-in-the-Middle attacks via conflicting ARP replies

## How It Works
It uses a sliding time-window algorithm. For each source IP, it counts 
packets within a configurable time window. When the count crosses 
a threshold, an alert is raised instantly in the terminal. All alerts 
are saved to a text log and a structured JSON report.

## Installation
pip install scapy colorama

## Usage
sudo python3 netids.py -i eth0
sudo python3 netids.py -i eth0 -t 120 -o alerts.txt
sudo python3 netids.py --list-interfaces

## Tech Stack
Python 3 · Scapy · Kali Linux

## Screenshots
<img width="815" height="435" alt="Screenshot 2026-06-20 221540" src="https://github.com/user-attachments/assets/8decb906-a53c-41a4-bff5-8183a3baf300" />
<img width="809" height="447" alt="Screenshot 2026-06-20 221508" src="https://github.com/user-attachments/assets/5bf8db0b-f5fb-4400-885d-83dbb7f89fd9" />
<img width="643" height="263" alt="Screenshot 2026-06-20 221123" src="https://github.com/user-attachments/assets/682aa9b2-1ab0-47e2-b102-aa42fad8a6a7" />
<img width="628" height="252" alt="Screenshot 2026-06-20 220949" src="https://github.com/user-attachments/assets/e72a17ff-5e36-4d0b-9104-cb5bc3ed6a7b" />
<img width="321" height="240" alt="Screenshot 2026-06-20 220008(1)" src="https://github.com/user-attachments/assets/8e16e2a6-2295-4eea-8ea1-984466b15059" />
