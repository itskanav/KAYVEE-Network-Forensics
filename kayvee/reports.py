"""Forensic report builders (JSON / CSV / PDF). Reports only contain data produced by the analysis of the stored evidence."""
import json, csv, io, datetime
from .netutil import human_bytes

LIMITS = [
    "Detections are heuristic indicators for analyst validation, not proof of malicious activity.",
    "TLS/HTTPS payloads are not decrypted; only handshake metadata (SNI, JA3, versions) is extracted.",
    "TCP reassembly is limited to the first 1 MB per direction and does not repair large capture gaps.",
    "GeoIP and threat-intelligence results depend on the databases/IOC lists loaded on the analysis workstation.",
    "The SHA-256 hash proves file integrity since acquisition; it does not replace documented chain-of-custody procedures.",
]


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "-"


def json_report(R, case, ev, custody, notes, analyst):
    S = R["summary"]
    doc = {"project": "KAYVEE Network Forensics Platform", "generated_utc": utc(__import__("time").time()), "analyst": analyst, "case": case,
           "evidence": {"filename": ev["filename"], "size_bytes": ev["size"], "sha256": ev["sha256"], "source": ev["source"], "acquired_utc": utc(ev["acquired_at"]),
                        "last_verification": ev["last_verify_status"], "last_verified_utc": utc(ev["last_verified_at"])},
           "chain_of_custody": custody, "summary": S, "alerts": R["alerts"], "hosts": R["hosts"][:200], "dns_top_domains": R["dns"]["top_domains"], "timeline": R["timeline"],
           "analyst_notes": notes, "limitations": LIMITS}
    return json.dumps(doc, indent=2, default=str).encode()


def csv_report(R, which):
    out = io.StringIO()
    w = csv.writer(out)
    if which == "alerts":
        w.writerow(["id", "severity", "score", "confidence", "rule", "category", "title", "actor", "target", "start_utc", "end_utc", "mitre", "description", "reason", "packet_numbers", "status"])
        for a in R["alerts"]:
            w.writerow([a["id"], a["severity"], a["score"], a["confidence"], a["rule"], a["category"], a["title"], a["src"], a["dst"], utc(a["ts_start"]), utc(a["ts_end"]), a["mitre_id"], a["description"], a["reason"], " ".join(map(str, a["packet_nos"])), a.get("status", "")])
    elif which == "hosts":
        w.writerow(["ip", "class", "score", "level", "pkts_out", "pkts_in", "bytes_out", "bytes_in", "first_utc", "last_utc", "macs", "names", "country", "city", "asn", "org"])
        for h in R["hosts"]:
            g = h["geo"] or {}
            w.writerow([h["ip"], h["class"], h["score"], h["level"], h["pkts_out"], h["pkts_in"], h["bytes_out"], h["bytes_in"], utc(h["first"]), utc(h["last"]), " ".join(h["macs"]), " ".join(h["names"]), g.get("country", ""), g.get("city", ""), g.get("asn", ""), g.get("org", "")])
    elif which == "flows":
        w.writerow(["id", "proto", "client", "cport", "server", "sport", "service", "app", "state", "start_utc", "duration_s", "c_pkts", "s_pkts", "c_bytes", "s_bytes", "c_payload", "s_payload"])
        for f in R["flows"]:
            w.writerow([f["id"], f["proto"], f["client"], f["cport"], f["server"], f["sport"], f["service"], f["app"], f["state"], utc(f["start"]), f["duration"], f["c_pkts"], f["s_pkts"], f["c_bytes"], f["s_bytes"], f["c_pl"], f["s_pl"]])
    elif which == "dns":
        w.writerow(["packet", "time_utc", "client/src", "server/dst", "name", "type", "response", "rcode", "answers"])
        for d in R["dns"]["records"]:
            w.writerow([d["no"], utc(d["ts"]), d["src"], d["dst"], d["qname"], d["qtype"], d["response"], d["rcode"], " | ".join("%s %s" % (a["type"], a["data"]) for a in d["answers"])])
    elif which == "timeline":
        w.writerow(["time_utc", "kind", "severity", "title", "src", "dst", "alert", "packets"])
        for e in R["timeline"]:
            w.writerow([utc(e["ts"]), e["kind"], e["severity"], e["title"], e["src"], e["dst"], e["alert"], " ".join(map(str, e["packet_nos"]))])
    else:
        raise ValueError("Unknown CSV dataset")
    return out.getvalue().encode("utf-8-sig")


def pdf_report(path, R, case, ev, custody, notes, analyst, iocs_loaded):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    NAVY, BLUE, CYAN = colors.HexColor("#172B4D"), colors.HexColor("#2457D6"), colors.HexColor("#00CFE8")
    SEV = {"Critical": "#E94B64", "High": "#FF9D42", "Medium": "#E8B029", "Low": "#00CFE8", "Info": "#8DA2C0"}
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=NAVY, fontSize=20, spaceAfter=6)
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=BLUE, fontSize=13, spaceBefore=10, spaceAfter=4)
    B = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12, textColor=NAVY)
    SM = ParagraphStyle("sm", parent=B, fontSize=7.5, leading=9.5)
    P = lambda t, s=B: Paragraph(str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), s)
    S = R["summary"]

    def tbl(rows, widths, head=True, sev_col=None):
        t = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
        st = [("FONTSIZE", (0, 0), (-1, -1), 7.5), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9D6EA")),
              ("TEXTCOLOR", (0, 0), (-1, -1), NAVY)]
        if head:
            st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EAF4FF")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        if sev_col is not None:
            for i, r in enumerate(rows[1:], 1):
                c = SEV.get(r[sev_col].text if hasattr(r[sev_col], "text") else r[sev_col])
                if c:
                    st.append(("TEXTCOLOR", (sev_col, i), (sev_col, i), colors.HexColor(c)))
                    st.append(("FONTNAME", (sev_col, i), (sev_col, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(st))
        return t

    def deco(c, d):
        c.saveState()
        c.setFillColor(CYAN); c.rect(0, A4[1] - 6, A4[0], 6, stroke=0, fill=1)
        c.setFont("Helvetica", 7); c.setFillColor(colors.HexColor("#5B6B8A"))
        c.drawString(15 * mm, 9 * mm, "KAYVEE Network Forensics - Case %s - Evidence SHA-256 %s" % (case["case_no"], ev["sha256"][:24] + "…"))
        c.drawRightString(A4[0] - 15 * mm, 9 * mm, "Page %d" % d.page)
        c.restoreState()

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm, bottomMargin=16 * mm, title="KAYVEE Forensic Report - %s" % case["case_no"], author=analyst)
    E = [P("KAYVEE", ParagraphStyle("lg", parent=H1, fontSize=30, textColor=BLUE)), P("Network Forensic Investigation Report", H1), Spacer(1, 4)]
    meta = [["Case", "%s - %s" % (case["case_no"], case["title"])], ["Analyst", analyst], ["Report generated", utc(__import__("time").time())], ["Evidence file", ev["filename"]],
            ["Evidence size", "%s (%d bytes)" % (human_bytes(ev["size"]), ev["size"])], ["Evidence SHA-256", ev["sha256"]], ["Acquisition", "%s by %s on %s" % (ev["source"], ev["acquired_by"], utc(ev["acquired_at"]))],
            ["Last integrity check", "%s at %s" % (ev["last_verify_status"] or "not yet verified", utc(ev["last_verified_at"]))], ["Capture window", "%s → %s (%.1fs)" % (utc(S["t0"]), utc(S["t1"]), S["duration"])]]
    E.append(tbl([[P(a, SM), P(b, SM)] for a, b in meta], [38 * mm, 142 * mm], head=False))
    E += [P("1. Executive summary", H2)]
    sev = S["alerts_by_severity"]
    E.append(P("The capture contains %s packets (%s) between %d hosts across %d flows. The rule engine raised %d indicator(s): %s. Overall case threat score: %d/100 (%s). "
               "Scores combine rule severity and confidence and are decision support only." % (format(S["packets"], ","), human_bytes(S["bytes"]), S["hosts"], S["flows"], S["alerts"],
                                                                                              ", ".join("%d %s" % (v, k) for k, v in sorted(sev.items(), key=lambda kv: -kv[1])) or "none", S["case_score"], S["case_level"])))
    E.append(P("2. Findings", H2))
    rows = [["ID", "Severity", "Score", "Finding", "Actor → Target", "First seen"]]
    for a in R["alerts"][:40]:
        rows.append([P(a["id"], SM), a["severity"], str(a["score"]), P(a["title"], SM), P("%s → %s" % (a["src"] or "-", a["dst"] or "-"), SM), P(utc(a["ts_start"]).replace(" UTC", ""), SM)])
    E.append(tbl(rows, [14 * mm, 17 * mm, 11 * mm, 72 * mm, 45 * mm, 21 * mm], sev_col=1) if len(rows) > 1 else P("No detection rules fired on this capture."))
    for a in R["alerts"][:12]:
        E.append(KeepTogether([P("%s  %s  (%s, confidence %d%%)" % (a["id"], a["title"], a["severity"], a["confidence"] * 100), ParagraphStyle("x", parent=B, fontName="Helvetica-Bold", spaceBefore=6)),
                               P(a["description"]), P("Why detected: " + a["reason"], SM), P("Evidence: " + "; ".join(a["evidence"][:5]), SM), P("Packets: " + (", ".join(map(str, a["packet_nos"][:25])) or "n/a") + ("  |  MITRE ATT&CK " + a["mitre_id"] if a["mitre_id"] else ""), SM),
                               P("Recommendation: " + (a["recommendation"] or "Validate manually."), SM)]))
    E.append(P("3. Top hosts", H2))
    rows = [["IP", "Class", "Score", "Packets out/in", "Bytes out/in", "Names / location"]]
    for h in R["hosts"][:15]:
        g = h["geo"]
        rows.append([P(h["ip"], SM), h["class"], "%d %s" % (h["score"], h["level"]), "%d / %d" % (h["pkts_out"], h["pkts_in"]), "%s / %s" % (human_bytes(h["bytes_out"]), human_bytes(h["bytes_in"])), P(", ".join(h["names"][:2]) or (g["city"] + " " + g["country"] if g else "-"), SM)])
    E.append(tbl(rows, [32 * mm, 20 * mm, 22 * mm, 30 * mm, 36 * mm, 40 * mm]))
    if R["dns"]["top_domains"]:
        E.append(P("4. DNS activity", H2))
        E.append(P("%d queries, %d unique names, %d NXDOMAIN responses." % (R["dns"]["queries"], R["dns"]["unique_names"], R["dns"]["nxdomain"])))
        E.append(tbl([["Domain", "Queries"]] + [[P(d, SM), str(n)] for d, n in R["dns"]["top_domains"][:12]], [120 * mm, 30 * mm]))
    E.append(P("5. Attack timeline", H2))
    E.append(tbl([["Time (UTC)", "Severity", "Event"]] + [[P(utc(e["ts"]).replace(" UTC", ""), SM), e["severity"], P(e["title"], SM)] for e in R["timeline"][:50]], [34 * mm, 20 * mm, 126 * mm], sev_col=1))
    E.append(P("6. Chain of custody", H2))
    E.append(tbl([["Time (UTC)", "Actor", "Action", "Details"]] + [[P(utc(c["ts"]).replace(" UTC", ""), SM), P(c["actor"], SM), P(c["action"], SM), P(c["details"][:140], SM)] for c in custody], [34 * mm, 28 * mm, 30 * mm, 88 * mm]))
    E.append(P("7. Analyst notes", H2))
    E += [P("%s (%s): %s" % (n["author"], utc(n["ts"]), n["text"])) for n in notes] or [P("No analyst notes recorded.")]
    E.append(P("8. Method and limitations", H2))
    E.append(P("Parsed with the KAYVEE pure-Python PCAP/PCAPNG engine. Threat-intelligence matching: %s." % ("performed against the loaded IOC list" if iocs_loaded else "not performed (no IOC list loaded)")))
    E += [P("• " + l, SM) for l in LIMITS]
    doc.build(E, onFirstPage=deco, onLaterPages=deco)
