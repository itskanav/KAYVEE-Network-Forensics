"""Local investigation assistant. Rule-based and fully offline: it explains and prioritises what the analysis already found.
It never invents facts - every statement is derived from the stored analysis result."""
import re
from .netutil import human_bytes

NEXT_STEPS = {
    "PORT_SCAN": "Review firewall/IDS logs for the scanning source, close unneeded services on the target and confirm the open ports are expected.",
    "BRUTE_FORCE": "Check authentication logs on the target for successful logins after the failures; enforce lockouts, MFA or key-based auth.",
    "ARP_SPOOF": "Compare ARP tables with switch CAM/DHCP records, locate the switch port of the conflicting MAC and enable Dynamic ARP Inspection.",
    "IP_SPOOF": "Verify network topology (routers/NAT/VMs can explain some indicators) and enable ingress filtering (BCP38).",
    "DDOS": "Engage upstream mitigation, enable SYN cookies/rate limiting and keep flow logs; spoofed sources limit attribution.",
    "DNS_TUNNEL": "Sinkhole the suspect domain, inspect the querying host for tunnelling tools and restrict outbound DNS to approved resolvers.",
    "DGA": "Identify the process generating failed lookups on the host and scan it for malware.",
    "EXFIL": "Identify what data left, check DLP/proxy logs and confirm whether the destination is approved; consider isolating the host.",
    "BEACON": "Identify the process making periodic calls; pivot on the destination (SNI/Host/JA3) and review other hosts talking to it.",
    "IOC": "Treat the matching host as potentially compromised; hunt for the same indicator in endpoint and proxy telemetry.",
    "CLEARTEXT": "Move to encrypted protocols and rotate credentials that crossed the network in cleartext.",
    "ICMP_TUNNEL": "Inspect ICMP payload content and restrict ICMP at the perimeter.",
    "ANOMALY": "Treat as a lead only: correlate with the other findings before escalating.",
    "SUSPICIOUS_PORT": "Check which process opened the connection and whether the port is expected.",
}


def narrative(R):
    S, al = R["summary"], R["alerts"]
    t = ["The capture holds %s packets (%s) over %.1f s between %d hosts." % (format(S["packets"], ","), human_bytes(S["bytes"]), S["duration"], S["hosts"])]
    if not al:
        t.append("No detection rule fired. That does not prove the traffic is benign - encrypted payloads and activity outside the rule coverage are not visible.")
        return " ".join(t)
    sev = S["alerts_by_severity"]
    t.append("%d indicators were raised (%s); the case threat score is %d/100 (%s)." % (len(al), ", ".join("%d %s" % (v, k) for k, v in sorted(sev.items(), key=lambda kv: -kv[1])), S["case_score"], S["case_level"]))
    worst = max(R["hosts"], key=lambda h: h["score"]) if R["hosts"] else None
    if worst and worst["score"] > 0:
        t.append("The highest-scoring host is %s (%d, %s) involved in %d finding(s)." % (worst["ip"], worst["score"], worst["level"], len(worst["alerts"])))
    cats = []
    for a in al:
        if a["category"] not in cats and a["severity"] in ("Critical", "High", "Medium"):
            cats.append(a["category"])
    if cats:
        t.append("Activity classes observed: %s." % ", ".join(c.replace("_", " ").lower() for c in cats[:6]))
    t.append("Findings are heuristic indicators and need analyst validation.")
    return " ".join(t)


def recommendations(R, limit=6):
    seen, out = set(), []
    for a in R["alerts"]:
        if a["category"] in seen or a["severity"] == "Info":
            continue
        seen.add(a["category"])
        out.append({"alert": a["id"], "severity": a["severity"], "title": a["title"], "action": a["recommendation"] or NEXT_STEPS.get(a["category"], "Validate manually.")})
        if len(out) >= limit:
            break
    return out


def answer(q, R):
    ql, S, al = q.lower().strip(), R["summary"], R["alerts"]
    refs = []
    if not ql:
        return {"answer": "Ask about the summary, riskiest host, a specific IP, alerts, DNS, scans, exfiltration or next steps.", "refs": []}
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ql)
    if m:
        h = next((h for h in R["hosts"] if h["ip"] == m.group(1)), None)
        if not h:
            return {"answer": "%s does not appear in this capture." % m.group(1), "refs": []}
        rel = [a for a in al if a["id"] in h["alerts"]]
        txt = "%s is a %s address, %s. It sent %d packets (%s) and received %d (%s)." % (h["ip"], h["class"], h["role"], h["pkts_out"], human_bytes(h["bytes_out"]), h["pkts_in"], human_bytes(h["bytes_in"]))
        if h["names"]: txt += " DNS answers in this capture map it to %s." % ", ".join(h["names"][:3])
        txt += (" Threat score %d (%s); it appears in: %s." % (h["score"], h["level"], "; ".join("%s %s" % (a["id"], a["title"]) for a in rel[:5]))) if rel else " No detection rule involves this host."
        return {"answer": txt, "refs": [{"type": "ip", "value": h["ip"]}] + [{"type": "alert", "value": a["id"]} for a in rel[:5]]}
    m = re.search(r"\ba-\d{3}\b", ql)
    if m:
        a = next((a for a in al if a["id"].lower() == m.group(0)), None)
        if a:
            return {"answer": "%s - %s (%s, score %d). %s Why it fired: %s Suggested action: %s" % (a["id"], a["title"], a["severity"], a["score"], a["description"], a["reason"], a["recommendation"] or NEXT_STEPS.get(a["category"], "Validate manually.")),
                    "refs": [{"type": "alert", "value": a["id"]}]}
    if any(k in ql for k in ("summar", "overview", "what happened", "tell me about")):
        return {"answer": narrative(R), "refs": []}
    if any(k in ql for k in ("risk", "danger", "worst", "attacker", "most suspicious", "top threat")):
        hs = sorted([h for h in R["hosts"] if h["score"] > 0], key=lambda h: -h["score"])[:5]
        if not hs: return {"answer": "No host has a non-zero threat score in this analysis.", "refs": []}
        return {"answer": "Highest-risk hosts: " + "; ".join("%s (score %d, %d finding(s))" % (h["ip"], h["score"], len(h["alerts"])) for h in hs) + ".", "refs": [{"type": "ip", "value": h["ip"]} for h in hs]}
    for kw, cat, label in (("scan", "PORT_SCAN", "scanning"), ("brute", "BRUTE_FORCE", "brute-force"), ("arp", "ARP_SPOOF", "ARP spoofing"), ("spoof", "IP_SPOOF", "IP spoofing"), ("ddos", "DDOS", "DDoS/DoS"), ("flood", "DDOS", "DDoS/DoS"),
                           ("tunnel", "DNS_TUNNEL", "DNS tunnelling"), ("exfil", "EXFIL", "exfiltration"), ("upload", "EXFIL", "exfiltration"), ("beacon", "BEACON", "beaconing"), ("c2", "BEACON", "beaconing"),
                           ("ioc", "IOC", "IOC"), ("intel", "IOC", "IOC"), ("malware", "BEACON", "malware-communication")):
        if kw in ql:
            hits = [a for a in al if a["category"] == cat]
            if not hits:
                return {"answer": "No %s indicators were raised in this analysis." % label, "refs": []}
            return {"answer": "%d %s finding(s): " % (len(hits), label) + "; ".join("%s %s [%s]" % (a["id"], a["title"], a["severity"]) for a in hits[:6]) + ". " + NEXT_STEPS.get(cat, ""), "refs": [{"type": "alert", "value": a["id"]} for a in hits[:6]]}
    if "dns" in ql:
        d = R["dns"]
        return {"answer": "%d DNS queries for %d unique names; %d NXDOMAIN responses. Top domains: %s." % (d["queries"], d["unique_names"], d["nxdomain"], ", ".join("%s (%d)" % x for x in d["top_domains"][:5]) or "none"), "refs": []}
    if any(k in ql for k in ("next", "recommend", "should i", "what do i do", "action")):
        r = recommendations(R)
        return {"answer": "Suggested order of work: " + " ".join("%d) %s - %s" % (i + 1, x["title"], x["action"]) for i, x in enumerate(r)) if r else "Nothing was flagged; consider widening the capture window or loading IOC lists.", "refs": [{"type": "alert", "value": x["alert"]} for x in r]}
    if any(k in ql for k in ("protocol", "traffic")):
        return {"answer": "Protocols by packets: " + ", ".join("%s %d" % kv for kv in list(S["protocols"].items())[:8]) + ".", "refs": []}
    return {"answer": "I can answer from this analysis only. Try: 'summary', 'riskiest host', 'explain A-001', 'tell me about 192.168.1.10', 'any scans?', 'dns activity', or 'what should I do next?'.", "refs": []}
