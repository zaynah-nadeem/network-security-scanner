# Network Security Scanner & Firewall Visualizer

A web-based tool that scans a local computer or network for open ports, services and possible vulnerabilities, and includes a firewall rule simulator with a visual flow diagram.

## Features

- Scan a single IP, a hostname or a local network (up to /24)
- Scan types: TCP Full Connect, TCP SYN and UDP
- Custom port ranges (e.g. `22,80,443` or `1-1024`)
- Results table with IP, port, protocol, service, version, status and risk level
- Risk level (High / Medium / Low) for each open port, with a reason
- Firewall rules with ALLOW/DENY, destination IP or network, port or port range, and protocol
- Priority-based rule chaining (first match wins) with a configurable default policy
- Colour-coded flow diagram showing how each packet is handled
- Only local and private targets are allowed, for safety

## Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **Scanning:** Nmap with python-nmap

## Setup

1. Install [Nmap](https://nmap.org/download.html) (on Windows, keep Npcap selected).
2. Install the Python libraries:
   ```
   pip install -r requirements.txt
   ```
3. Run the app:
   ```
   python app.py
   ```
4. Open http://127.0.0.1:5000 in your browser.

TCP SYN and UDP scans need administrator/root rights. TCP Full Connect works without them.

## Project Structure

```
network-security-scanner/
├── app.py                Flask backend, scanning and firewall logic
├── templates/
│   └── index.html        User interface
├── requirements.txt      Python libraries
└── README.md
```

## Disclaimer

Only scan computers and networks you own or have permission to test.