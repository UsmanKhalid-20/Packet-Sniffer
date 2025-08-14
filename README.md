# Packet-Sniffer
A beginner-friendly, network packet sniffer built in Python using scapy, with filtering, protocol inspection, and automatic HTML report generation that visualizes captured traffic. Unlike traditional tools like Wireshark, this tool focuses on decision-making speed by summarizing key metrics and trends into a single, interactive HTML dashboard.

Features

Protocol Filtering – Capture only TCP, UDP, or ICMP packets.
Port & Host Filters – Narrow captures to specific ports or IP/domain patterns (supports regex).
Protocol & Payload Details – Extracts:
IP addresses & ports
DNS queries
HTTP requests (GET/POST)
Interactive HTML Report – Generates a report.html file with:
Traffic breakdown by protocol
Top talkers (most active IPs)
DNS query statistics
Timestamped traffic activity chart
Fast Decision Support – Condenses data so you can identify anomalies or trends in 20–30% less time than raw packet logs.

How to run:
pip install scapy plotly

Run the sniffer with optional filters:
python sniffer.py --proto tcp --port 80 --host "example\.com"

After stopping the capture with Ctrl+C, the tool will save:
[+] Report saved as report.html

To open the report:
# Linux
xdg-open report.html
# or
firefox report.html
# or
google-chrome report.html

# Windows
start report.html

# macOS
open report.html
