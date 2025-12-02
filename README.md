Device Network Monitoring

A cross-platform GUI application for real-time network traffic monitoring, process-to-connection mapping, and GeoIP-based threat detection. This tool provides an interactive interface showing live network packets, process activity, geographical IP information, and alerts for suspicious behavior.

Repository: https://github.com/CoderNjoro/Device-Network-Monitoring

Features

Real-time packet capture using scapy (requires administrative privileges)
Process mapping that connects network traffic to running applications using psutil
GeoIP intelligence that looks up destination IPs via ip-api.com with request caching
Suspicious activity detection for unusual ports, multiple destinations, port scanning patterns, and high-risk countries
Multi-tab graphical interface with live packet display, process activity view, GeoIP summary, suspicious process alerts, and activity log

Requirements

Python version 3.8 or higher recommended
Administrative privileges on Windows or root access on Linux/macOS for packet capture
Required Python packages: scapy, psutil, and requests (optional but recommended for GeoIP)

Installation with pip (from project directory):
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install scapy psutil requests

Or create a requirements.txt file containing:
scapy
psutil
requests

Then install with: pip install -r requirements.txt

Quick Start

Open a terminal in the project folder (for example: c:\Users\Tech\Desktop\Network Traffic Monitor)
Activate your virtual environment if using one, install required packages, then run:
cd "C:\Users\Tech\Desktop\Network Traffic Monitor"
python Device_Network_Monitoring.py

When you click Start Monitoring, the application begins live packet capture. On Windows and macOS, administrative privileges are typically required. Run your terminal as Administrator on Windows or use sudo on macOS/Linux.

Notes and Troubleshooting

If scapy is not installed, the application displays an error and exits. Install all required packages first.
GeoIP lookups use ip-api.com with a short timeout. Without the requests package, the tool falls back to DNS reverse resolution.
On Windows, some port and process lookups may fail without Administrator permissions. Run with elevated privileges.
If you see frequent Unknown process names, check psutil permissions and ensure the script runs with sufficient privileges.

Security and Privacy

This tool performs network packet capture and may log sensitive information including IP addresses and hostnames. Use only on networks and devices you own or have authorization to monitor.
GeoIP queries are sent to third-party service ip-api.com. Ensure this complies with your privacy requirements and organizational policies.

Development and Contribution

Issues and pull requests are welcome on the GitHub repository. Potential improvements include:

Adding a requirements.txt or pyproject.toml file
Implementing automated tests and continuous integration
Adding log persistence to disk or export to CSV/JSON formats
Enhancing secure remote connection handling

Running and Packaging

To create a standalone executable using pyinstaller:
pip install pyinstaller
pyinstaller --onefile Device_Network_Monitoring.py

Contact and License

Repository: https://github.com/CoderNjoro/Device-Network-Monitoring
A LICENSE file can be added with your preferred license (MIT, Apache-2.0, GPL-3.0, etc.)

Additional options include:
Adding a requirements.txt with specific package versions
Creating a run.bat or PowerShell script for Windows that requests elevated privileges
Including more detailed setup and configuration documentation

**This are the screenshots of the system**
<img width="1337" height="728" alt="02 12 2025_15 12 02_REC" src="https://github.com/user-attachments/assets/bf7041cf-9062-4614-b9b5-502d5cf39c8d" />
<img width="1353" height="715" alt="02 12 2025_15 12 26_REC" src="https://github.com/user-attachments/assets/3c4e4d66-0702-484c-b86c-3f78b41085b6" />

