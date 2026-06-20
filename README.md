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

<img width="321" height="240" alt="Screenshot 2026-06-20 220008(1)" src="https://github.com/user-attachments/assets/434f70db-93cb-4dc5-9184-1b039f3e22ae" />
<img width="628" height="252" alt="Screenshot 2026-06-20 220949" src="https://github.com/user-attachments/assets/f71e0424-0bcd-4a4b-82ec-bc67fc37f6c4" />
<img width="643" height="263" alt="Screenshot 2026-06-20 221123" src="https://github.com/user-attachments/assets/bf86311c-831f-40dd-8774-00a0505a8d57" />

<img width="809" height="447" alt="Screenshot 2026-06-20 221508" src="https://github.com/user-attachments/assets/5cf7835d-8091-4362-a2c4-55a7a94933a2" />

<img width="815" height="435" alt="Screenshot 2026-06-20 221540" src="https://github.com/user-attachments/assets/61013263-f46f-4a2b-819f-e3d852fbb9b5" />


