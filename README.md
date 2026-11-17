# KAYVEE Network Forensics Platform v2

Light holographic network-forensics workstation. Pure-Python engine (no Scapy, no Streamlit) + Flask API + dependency-free web UI.
The original Streamlit prototype is preserved untouched in `legacy_streamlit/`.

## Run
```
pip install -r requirements.txt        # Flask is the only hard requirement
python app.py                           # http://127.0.0.1:5000   (local only by default)
sudo python3 app.py                     # Linux: enables live capture
python tests/smoke_test.py              # optional end-to-end self-test
```
Windows: double-click `run.bat`. Data (evidence, DB, reports) lives in `data/` (override with `KAYVEE_DATA`).

## Why the old tool probably failed
The prototype needed Scapy + Streamlit + pandas. Common breakers: Scapy/Npcap install on Windows, `scapy` 2.6 changing DNS `qd` to a list
(DNS parsing silently failed), reading PCAPNG from `BytesIO`, and Streamlit/pandas version drift. v2 parses PCAP/PCAPNG itself, so none of that applies.

## Feature map
| Area | Where | Notes |
|---|---|---|
| PCAP/PCAPNG analysis, IP/protocol/DNS extraction | PCAP Analyzer | Ethernet, VLAN, Linux-SLL, raw IP, IPv4/IPv6, TCP/UDP/ICMP/ARP |
| Live capture | Live Network Monitoring | Linux AF_PACKET (root) or Scapy if installed (Scapy path is untested). Output is a sealed evidence PCAP |
| Port scan, brute force, ARP/IP spoofing, DDoS, DNS tunnelling/DGA, exfiltration, beaconing, anomalies | Threat Detection | Every finding lists reason, threshold, packets, MITRE ID |
| TCP reconstruction, sessions, HTTP, TLS/SNI/JA3 | TCP Stream Analysis | First 1 MB per direction; HTTPS is **not** decrypted |
| IOC matching / threat intel | Threat Detection → Threat intelligence | IP, CIDR, domain, URL, JA3. Paste/CSV/JSON or fetch a feed URL you choose |
| GeoIP | IP Intelligence | Needs your own `GeoLite2-City.mmdb` in `data/geoip/` + `pip install maxminddb`. Without it: "unavailable" (never guessed) |
| Evidence, SHA-256, chain of custody | Evidence Manager | Hash on arrival, re-checked before every analysis, hash-chained custody log detects edits |
| Cases, notes, history, alert triage | Case Management | |
| Reports | Investigation Reports | PDF, JSON, CSV (findings/hosts/flows/DNS/timeline); each report is hashed and logged |
| Notifications | Bell icon | New findings ≥ chosen severity, failed integrity checks, finished analyses |
| AI-assisted investigation | right panel | **Local rule-based** assistant answering only from the analysis. No LLM, nothing leaves the machine |

## Honest limits
* Detections are heuristics. Thresholds are editable in Settings. Expect false positives (e.g. legitimate periodic traffic).
* Globe: hosts with a GeoIP record sit at their real coordinates; others orbit on rings and are labelled *unlocated*.
* No IP-fragment reassembly, no TLS decryption, analysis capped at 500,000 packets (noted in the UI when hit).
* `tests/make_test_pcap.py` builds a synthetic lab capture for self-testing only; the app never generates data.
