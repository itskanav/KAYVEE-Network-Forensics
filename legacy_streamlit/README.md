# KAYVEE Network Forensics & Threat Detection

A Streamlit educational prototype for analyzing authorized PCAP/PCAPNG captures with two logical models.

## Features

### Model 1 — Core analysis
- Packet metadata parsing with Scapy
- IPv4/IPv6 endpoints, TCP/UDP/ICMP, ports, lengths and timestamps
- DNS query metadata and simple long/high-entropy label indicator
- Basic HTTP request metadata; flags authorization/cookie header presence without retaining their values
- Directional conversation summary and duration
- SHA-256 evidence hash
- CSV and JSON export

### Model 2 — Detection
- DNS volume / long-label heuristic
- Port-scan heuristic based on distinct destination ports
- Repeated-connection heuristic (not definitive brute-force detection)
- Per-source packet-volume statistical outlier
- Artifact indicator alerts

## Run on Linux / Kali

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip libpcap-dev
cd kayvee_network_forensics
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL Streamlit prints, usually `http://localhost:8501`.

## Run on Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Scapy may require Npcap on Windows for some packet operations. Offline PCAP reading is the main workflow.

## How to use
1. Open the dashboard.
2. Enter a case ID and analyst label.
3. Upload a PCAP/PCAPNG file from an authorized lab.
4. Explore Overview, Model 1, Model 2, and Evidence & Export.
5. Save the JSON report and CSVs with the original evidence file.

## Limitations
- HTTPS is encrypted. This app does not recover plaintext credentials or decrypt HTTPS.
- TLS SNI/certificate parsing is not implemented yet; the TLS/HTTPS label is inferred from port 443.
- Threat-intelligence matching is not connected to a live feed.
- Detection rules are simple heuristics and may create false positives/negatives.
- Conversation duration is computed from observed directional endpoint packets, not reconstructed TCP streams.
- IP geolocation is not included; private IPs and inaccurate geolocation make maps misleading without a trusted GeoIP database.
- Evidence hash supports integrity checks but does not replace chain-of-custody documentation.

Use only captures you own or have permission to analyze.
