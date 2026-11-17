"""Rule-based detections. Every alert states what was observed, the threshold crossed and which packets support it.
These are indicators for analyst validation - not proof of compromise."""
import math, statistics
from collections import defaultdict, Counter
from . import dissect as D
from .netutil import ip_class, is_local, is_public, registered_domain, SEVERITY_SCORE, MITRE, noisy_or, level_for

DEFAULTS = {
    "scan_ports_per_target": 15, "scan_ports_total": 20, "sweep_hosts": 15,
    "bf_conns_per_min": 10, "bf_http_fail": 5, "bf_ftp_fail": 3, "bf_smtp_fail": 3, "repeat_flows": 25,
    "arp_unsolicited": 10, "mac_many_ips": 10,
    "ddos_syn": 200, "ddos_udp": 500, "ddos_icmp": 300, "ddos_dns_amp": 200, "ddos_sources": 20,
    "dns_unique_subs": 25, "dns_label_len": 45, "dns_entropy": 3.7, "dns_volume": 40, "dga_nx": 15,
    "exfil_bytes": 524288, "exfil_ratio": 8, "icmp_payload": 256,
    "beacon_min_conns": 8, "beacon_cv": 0.25, "z_host": 3.0, "z_bin": 4.0,
}
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
              5900: "VNC", 5985: "WinRM", 6379: "Redis", 27017: "MongoDB", 587: "SMTP-submission", 8080: "HTTP-alt"}
SUSPICIOUS_PORTS = {4444: "Metasploit default handler", 31337: "classic backdoor port", 12345: "NetBus-style backdoor", 1337: "common backdoor/leet port",
                    6667: "IRC (common botnet C2)", 9001: "Tor OR port", 5555: "ADB / RAT port", 6666: "IRC / backdoor", 54321: "backdoor port"}
NO_BEACON_PORTS = {123, 5353, 1900, 137, 138, 67, 68, 5355}


class Engine:
    def __init__(self, A, iocs=None, cfg=None):
        self.A, self.iocs = A, iocs or []
        self.c = dict(DEFAULTS, **(cfg or {}))
        self.alerts = []

    def add(self, rule, cat, title, sev, conf, actor, target, t0, t1, desc, reason, evidence, nos=(), rec="", extra=None):
        mid = MITRE.get(cat, ("", ""))
        self.alerts.append({"rule": rule, "category": cat, "title": title, "severity": sev, "confidence": round(conf, 2), "src": actor or "", "dst": target or "",
                            "ts_start": t0, "ts_end": t1, "description": desc, "reason": reason, "evidence": evidence[:30], "packet_nos": sorted(set(nos))[:150],
                            "recommendation": rec, "mitre_id": mid[0], "mitre_name": mid[1], "extra": extra or {},
                            "score": round(SEVERITY_SCORE[sev] * (0.6 + 0.4 * conf))})

    def run(self):
        for fn in (self.port_scan, self.brute_force, self.arp_spoof, self.ip_spoof, self.ddos, self.dns_rules, self.exfil, self.beacon,
                   self.ioc_match, self.anomalies, self.cleartext):
            try:
                fn()
            except Exception as ex:  # one failing rule must never abort the investigation
                self.add("RULE_ERROR", "ANOMALY", "Detection rule %s failed" % fn.__name__, "Info", 1, "", "", None, None,
                         "Rule crashed on this capture; remaining rules still ran.", "%s: %s" % (type(ex).__name__, ex), [])
        self.alerts.sort(key=lambda a: (-a["score"], a["ts_start"] or 0))
        for i, a in enumerate(self.alerts, 1):
            a["id"] = "A-%03d" % i
        return self.alerts

    # ---------------------------------------------------------------- port scan
    def port_scan(self):
        c, A = self.c, self.A
        per = defaultdict(lambda: defaultdict(lambda: {"ports": set(), "nos": [], "t0": None, "t1": None, "odd": 0}))
        for p in A.pkts:
            if p.proto != "TCP" or not p.src:
                continue
            syn_only = (p.flags & 0x12) == 0x02
            odd = p.flags in (0, 1, 0x29, 0x3F)
            if not (syn_only or odd):
                continue
            x = per[p.src][p.dst]
            x["ports"].add(p.dport); x["odd"] += odd
            if len(x["nos"]) < 60: x["nos"].append(p.no)
            x["t0"] = p.ts if x["t0"] is None else x["t0"]; x["t1"] = p.ts
        openp = defaultdict(set)
        for f in A.flow_list:
            if f["proto"] == "TCP" and f["synack"]:
                openp[(f["client"], f["server"])].add(f["sport"])
        done = set()
        for src, dsts in per.items():
            total = set().union(*[x["ports"] for x in dsts.values()])
            for dst, x in dsts.items():
                n = len(x["ports"])
                if n >= c["scan_ports_per_target"] or (n >= 10 and x["odd"] >= 10):
                    op = sorted(openp.get((src, dst), ()))
                    kind = "stealth (NULL/FIN/Xmas flag)" if x["odd"] >= 10 else "SYN"
                    sev = "High" if (n >= 100 or x["odd"] >= 10 or (n >= 40 and len(op) < n * 0.3)) else "Medium"
                    self.add("PORT_SCAN_VERTICAL", "PORT_SCAN", "Port scan: %s → %s" % (src, dst), sev, min(1, 0.55 + n / 200), src, dst, x["t0"], x["t1"],
                             "%s probed %d distinct TCP ports on %s using %s probes." % (src, n, dst, kind),
                             "Threshold: ≥%d distinct destination ports to one target from SYN-only/odd-flag packets. Observed %d; %d port(s) answered SYN-ACK." % (c["scan_ports_per_target"], n, len(op)),
                             ["%d distinct ports probed" % n, "Open (SYN-ACK) ports: %s" % (", ".join(map(str, op[:25])) or "none observed"), "Ports sample: %s" % ", ".join(map(str, sorted(x["ports"])[:25]))],
                             x["nos"], "Block or rate-limit the source, review exposed services on the target (%s) and check firewall logs for earlier probing." % (", ".join(map(str, op[:6])) or "no open ports observed"))
                    done.add(src)
            if src not in done and len(total) >= c["scan_ports_total"]:
                nos = [n for x in dsts.values() for n in x["nos"]][:60]
                self.add("PORT_SCAN_HEURISTIC", "PORT_SCAN", "Many destination ports from %s" % src, "Medium", 0.5, src, "", min(x["t0"] for x in dsts.values()), max(x["t1"] for x in dsts.values()),
                         "%s contacted %d distinct TCP destination ports across %d host(s)." % (src, len(total), len(dsts)),
                         "Legacy KAYVEE rule: ≥%d distinct destination ports from one source." % c["scan_ports_total"], ["%d unique destination ports" % len(total)], nos,
                         "Confirm whether this host is a scanner or a legitimate client.")
            # horizontal sweep
            byport = defaultdict(set)
            for dst, x in dsts.items():
                for pt in x["ports"]:
                    byport[pt].add(dst)
            for pt, hs in byport.items():
                if len(hs) >= c["sweep_hosts"]:
                    nos = [n for d in hs for n in dsts[d]["nos"][:2]]
                    self.add("HOST_SWEEP", "PORT_SCAN", "Host sweep on port %d from %s" % (pt, src), "High" if len(hs) >= 50 else "Medium", min(1, 0.6 + len(hs) / 150), src, "", min(dsts[d]["t0"] for d in hs), max(dsts[d]["t1"] for d in hs),
                             "%s probed port %d (%s) on %d different hosts." % (src, pt, D.SERVICES.get(pt, "unknown"), len(hs)),
                             "Threshold: ≥%d distinct hosts probed on the same port." % c["sweep_hosts"], ["%d hosts probed" % len(hs), "Sample targets: %s" % ", ".join(sorted(hs)[:10])], nos,
                             "Look for the same source in firewall/IDS logs; isolate if internal.")

    # ---------------------------------------------------------------- brute force
    def brute_force(self):
        c, A = self.c, self.A
        groups = defaultdict(list)
        for f in A.flow_list:
            if f["proto"] == "TCP" and f["sport"] in AUTH_PORTS and (f["syn"] or f["midstream"]):
                groups[(f["client"], f["server"], f["sport"])].append(f)
        flagged = set()
        for (cl, sv, pt), fl in groups.items():
            ts = sorted(f["start"] for f in fl)
            best, j = 0, 0
            for i in range(len(ts)):
                while ts[i] - ts[j] > 60:
                    j += 1
                best = max(best, i - j + 1)
            if best >= c["bf_conns_per_min"]:
                nos = [n for f in fl for n in f["pkt_nos"][:2]]
                ok = sum(1 for f in fl if f["synack"])
                sev = "High" if best >= 30 else "Medium"
                self.add("BRUTE_FORCE_RATE", "BRUTE_FORCE", "Possible %s brute force: %s → %s:%d" % (AUTH_PORTS[pt], cl, sv, pt), sev, min(1, 0.5 + best / 80), cl, sv, ts[0], ts[-1],
                         "%d connections to %s service on %s within 60s window (%d total in capture)." % (best, AUTH_PORTS[pt], sv, len(fl)),
                         "Threshold: ≥%d new connections per 60s from one client to an authentication service. Observed peak %d; %d completed handshakes." % (c["bf_conns_per_min"], best, ok),
                         ["Peak %d connections / 60s" % best, "Total connections: %d" % len(fl), "Completed handshakes: %d" % ok], nos,
                         "Check authentication logs on %s for failed logins from %s; enforce lockout/rate limits and key-based authentication." % (sv, cl))
                flagged.add((cl, sv, pt))
            elif len(fl) >= c["repeat_flows"] and (cl, sv, pt) not in flagged:
                self.add("REPEATED_CONNECTIONS", "BRUTE_FORCE", "Repeated connections: %s → %s:%d" % (cl, sv, pt), "Low", 0.4, cl, sv, ts[0], ts[-1],
                         "%d separate connections to %s service on %s." % (len(fl), AUTH_PORTS[pt], sv), "Legacy KAYVEE rule: ≥%d connections to one endpoint (not proof of brute force)." % c["repeat_flows"],
                         ["%d connections" % len(fl)], [n for f in fl for n in f["pkt_nos"][:1]])
        for (cl, sv, pt), cnt in A.auth_fail.items():
            for app, n in cnt.items():
                th = {"http": c["bf_http_fail"], "ftp": c["bf_ftp_fail"], "smtp": c["bf_smtp_fail"]}[app]
                if n >= th:
                    fl = [f for f in A.flow_list if f["client"] == cl and f["server"] == sv and f["sport"] == pt]
                    code = {"http": "HTTP 401/403", "ftp": "FTP 530", "smtp": "SMTP 535"}[app]
                    self.add("AUTH_FAILURES", "BRUTE_FORCE", "Repeated %s authentication failures: %s → %s" % (app.upper(), cl, sv), "High" if n >= th * 3 else "Medium", min(1, 0.6 + n / 60), cl, sv,
                             min(f["start"] for f in fl), max(f["end"] for f in fl), "%d %s authentication failure responses returned to %s." % (n, code, cl),
                             "Threshold: ≥%d %s responses in reassembled streams." % (th, code), ["%d × %s" % (n, code)], [x for f in fl for x in f["pkt_nos"][:3]],
                             "Review account lockouts on %s and whether any attempt succeeded afterwards." % sv)
        posts = Counter((t["client"], t["server"], t["uri"]) for t in A.http if t["method"] == "POST")
        for (cl, sv, uri), n in posts.items():
            if n >= 10:
                self.add("REPEATED_POST", "BRUTE_FORCE", "Repeated POSTs to %s" % uri[:60], "Medium", 0.5, cl, sv, None, None, "%d POST requests from %s to %s%s." % (n, cl, sv, uri[:80]),
                         "Threshold: ≥10 POST requests to the same URI (possible credential stuffing or automated form abuse).", ["%d POST requests" % n], [])

    # ---------------------------------------------------------------- ARP
    def arp_spoof(self):
        c, arp = self.c, self.A.arp
        if not arp:
            return
        ip_macs, mac_ips = defaultdict(lambda: defaultdict(list)), defaultdict(lambda: defaultdict(list))
        for a in arp:
            if a["spa"] in ("0.0.0.0", ""):
                continue
            if a["op"] in ("reply", "request"):
                ip_macs[a["spa"]][a["sha"]].append(a)
                mac_ips[a["sha"]][a["spa"]].append(a)
        for ip, ms in ip_macs.items():
            if len(ms) >= 2:
                evid = ["%s claimed by %s (%d ARP packets)" % (ip, m, len(v)) for m, v in ms.items()]
                nos = [x["no"] for v in ms.values() for x in v[:10]]
                allp = [x for v in ms.values() for x in v]
                self.add("ARP_IP_MAC_CONFLICT", "ARP_SPOOF", "ARP spoofing indicator: %s claimed by %d MACs" % (ip, len(ms)), "Critical" if len(ms) == 2 and any(len(v) >= 3 for v in ms.values()) else "High", 0.85,
                         sorted(ms, key=lambda m: ms[m][0]["ts"])[-1], ip, min(x["ts"] for x in allp), max(x["ts"] for x in allp),
                         "IP address %s is advertised via ARP from multiple hardware addresses: %s." % (ip, ", ".join(ms)),
                         "Rule: one IP bound to ≥2 MAC addresses within the capture - typical of ARP cache poisoning (also seen with failover/VRRP, so verify).", evid, nos,
                         "Compare against the switch CAM table / DHCP leases, enable Dynamic ARP Inspection, and clear ARP caches on affected hosts.")
        for m, ips in mac_ips.items():
            if len(ips) >= 3:
                allp = [x for v in ips.values() for x in v]
                self.add("ARP_MAC_MULTI_IP", "ARP_SPOOF", "One MAC claims %d IP addresses via ARP" % len(ips), "Medium", 0.5, m, "", min(x["ts"] for x in allp), max(x["ts"] for x in allp),
                         "MAC %s advertises %d IPs (%s)." % (m, len(ips), ", ".join(sorted(ips)[:8])), "Rule: ≥3 IP addresses announced by one MAC (gateway, proxy-ARP or poisoning).", ["%s → %s" % (m, ip) for ip in sorted(ips)[:10]],
                         [x["no"] for x in allp[:60]], "Verify whether this MAC is a router or hypervisor; otherwise investigate the port it is attached to.")
        reqs = {(a["spa"], a["tpa"]) for a in arp if a["op"] == "request"}
        unsol = defaultdict(list)
        for a in arp:
            if a["op"] == "reply" and (a["tpa"], a["spa"]) not in reqs:
                unsol[a["sha"]].append(a)
        for m, v in unsol.items():
            if len(v) >= c["arp_unsolicited"]:
                self.add("ARP_UNSOLICITED", "ARP_SPOOF", "Unsolicited ARP reply flood from %s" % m, "High", 0.7, m, "", v[0]["ts"], v[-1]["ts"],
                         "%d ARP replies from %s had no matching request." % (len(v), m), "Threshold: ≥%d unsolicited ARP replies (gratuitous poisoning pattern)." % c["arp_unsolicited"],
                         ["%d unsolicited replies" % len(v), "Claimed IPs: %s" % ", ".join(sorted({x["spa"] for x in v})[:8])], [x["no"] for x in v[:80]],
                         "Check the switch port for this MAC and enable Dynamic ARP Inspection.")
        mism = [a for a in arp if a["eth_src"] and a["sha"] and a["eth_src"] != a["sha"]]
        if len(mism) >= 3:
            self.add("ARP_ETH_MISMATCH", "ARP_SPOOF", "ARP sender MAC differs from Ethernet source", "High", 0.8, mism[0]["eth_src"], "", mism[0]["ts"], mism[-1]["ts"],
                     "%d ARP packets carry a sender hardware address that differs from the Ethernet source address." % len(mism), "Rule: ARP sha ≠ Ethernet source (forged ARP frames).",
                     ["%d mismatched frames" % len(mism)], [a["no"] for a in mism[:60]])

    # ---------------------------------------------------------------- IP spoofing indicators
    def ip_spoof(self):
        A, c = self.A, self.c
        land, bogon, mac_ips = [], defaultdict(list), defaultdict(set)
        ip_mac = defaultdict(Counter)
        for p in A.pkts:
            if not p.src or p.proto == "ARP":
                continue
            if p.src == p.dst and p.proto == "TCP" and (p.flags & 2):
                land.append(p)
            cl = ip_class(p.src)
            if cl in ("multicast", "broadcast") or (cl == "loopback" and p.eth_src) or (cl == "reserved" and p.src != "0.0.0.0") or \
               (p.src == "0.0.0.0" and not (p.proto == "UDP" and p.dport == 67)):
                bogon[(p.src, cl)].append(p)
            if p.eth_src:
                ip_mac[p.src][p.eth_src] += 1
                if is_local(p.src):
                    mac_ips[p.eth_src].add(p.src)
        if land:
            self.add("LAND_ATTACK", "IP_SPOOF", "LAND attack pattern (source = destination)", "High", 0.9, land[0].src, land[0].dst, land[0].ts, land[-1].ts, "%d SYN packets have identical source and destination address." % len(land),
                     "Rule: IP source equals destination on a TCP SYN.", ["%s:%s → itself" % (land[0].src, land[0].dport)], [p.no for p in land[:60]])
        for (ip, cl), ps in bogon.items():
            self.add("BOGON_SOURCE", "IP_SPOOF", "Invalid source address %s (%s)" % (ip, cl), "Medium", 0.6, ip, ps[0].dst, ps[0].ts, ps[-1].ts,
                     "%d packet(s) used a %s address as source on the wire." % (len(ps), cl), "Rule: multicast/broadcast/reserved/loopback source addresses are never valid on a network link.",
                     ["%d packets" % len(ps)], [p.no for p in ps[:60]], "Enable ingress filtering (BCP38/uRPF) at the network edge.")
        for m, ips in mac_ips.items():
            if len(ips) >= c["mac_many_ips"]:
                self.add("MAC_MANY_SOURCES", "IP_SPOOF", "One MAC sends traffic from %d local IPs" % len(ips), "Low", 0.4, m, "", None, None,
                         "MAC %s used %d different local source IPs: %s." % (m, len(ips), ", ".join(sorted(ips)[:6])), "Rule: ≥%d local source IPs behind one MAC (router, NAT/VM host or spoofing). Verify topology." % c["mac_many_ips"], ["%d source IPs" % len(ips)], [])
        for ip, macs in ip_mac.items():
            strong = [m for m, n in macs.items() if n >= 5]
            if len(strong) >= 2 and is_local(ip):
                self.add("IP_MULTI_MAC", "IP_SPOOF", "IP %s sourced from %d MAC addresses" % (ip, len(strong)), "Medium", 0.55, ip, "", None, None,
                         "Local address %s transmitted from %s." % (ip, ", ".join(strong)), "Rule: one local IP observed with ≥2 MACs (5+ packets each): duplicate IP, failover or spoofing.", ["%s: %d packets" % (m, macs[m]) for m in strong], [])
        for ip, h in A.hosts.items():
            if h["pkts_out"] < 30 or not h["ttls"]:
                continue
            b = Counter()
            for t, n in h["ttls"].items():
                b[32 if t <= 32 else 64 if t <= 64 else 128 if t <= 128 else 255] += n
            major = [k for k, n in b.items() if n >= max(15, 0.1 * h["pkts_out"])]
            if len(major) >= 2 and h["class"] in ("public", "private"):
                self.add("TTL_INCONSISTENT", "IP_SPOOF", "Inconsistent TTL fingerprint for %s" % ip, "Low", 0.35, ip, "", h["first"], h["last"],
                         "Packets from %s arrive with initial-TTL classes %s." % (ip, sorted(major)), "Rule: ≥2 initial-TTL classes (32/64/128/255) each ≥10%% of packets. May indicate spoofed packets mixed with genuine ones, NAT, or multiple devices.",
                         ["TTL distribution: %s" % ", ".join("%d×%d" % (t, n) for t, n in h["ttls"].most_common(6))], [])

    # ---------------------------------------------------------------- DDoS
    def ddos(self):
        A, c = self.A, self.c
        per = defaultdict(lambda: {"sec": Counter(), "syn": 0, "udp": 0, "icmp": 0, "dnsr": 0, "src": set(), "syn_src": set(), "nos": [], "t0": None, "t1": None, "synsec": Counter()})
        synack_from, dnsq_by = Counter(), Counter()
        for p in A.pkts:
            if not p.src:
                continue
            if p.proto == "TCP" and (p.flags & 0x12) == 0x12:
                synack_from[p.src] += 1
            if p.proto == "DNS" and p.dport == 53:
                dnsq_by[p.src] += 1
            x = per[p.dst]
            sec = int(p.ts)
            x["sec"][sec] += 1
            x["t0"] = p.ts if x["t0"] is None else x["t0"]; x["t1"] = p.ts
            if len(x["src"]) < 20000: x["src"].add(p.src)
            if p.proto == "TCP" and (p.flags & 0x12) == 0x02:
                x["syn"] += 1; x["synsec"][sec] += 1
                if len(x["syn_src"]) < 20000: x["syn_src"].add(p.src)
                if len(x["nos"]) < 80: x["nos"].append(p.no)
            elif p.proto == "UDP" and p.dport not in (53, 5353):
                x["udp"] += 1
                if len(x["nos"]) < 80 and x["udp"] % 5 == 0: x["nos"].append(p.no)
            elif p.proto == "ICMP" and p.icmp_type == 8:
                x["icmp"] += 1
                if len(x["nos"]) < 80: x["nos"].append(p.no)
            elif p.proto == "DNS" and p.sport == 53:
                x["dnsr"] += 1
                if len(x["nos"]) < 80 and x["dnsr"] % 3 == 0: x["nos"].append(p.no)
        for dst, x in per.items():
            if not dst or not x["sec"]:
                continue
            peak_s, peak = x["sec"].most_common(1)[0]
            srcs = len(x["src"])
            top = ", ".join(sorted(x["src"])[:5])

            def emit(kind, label, count, th, srcn, extra):
                dist = srcn >= c["ddos_sources"]
                sev = "Critical" if dist and count >= th * 3 else "High"
                self.add(kind, "DDOS", "%s %s → %s" % ("Distributed" if dist else "Single-source", label, dst), sev, min(1, 0.55 + count / (th * 6)), top if not dist else "%d sources" % srcn, dst, x["t0"], x["t1"],
                         "%d %s packets targeted %s from %d source address(es); peak %d packets in one second." % (count, label, dst, srcn, peak),
                         "Threshold: ≥%d %s packets. Observed %d from %d distinct sources." % (th, label, count, srcn), ["Peak rate: %d pkt/s at %s" % (peak, peak_s), "Unique sources: %d" % srcn, extra] + ["Sample sources: %s" % top], x["nos"],
                         "Engage upstream/ISP mitigation, enable SYN cookies and rate limiting, and preserve flow logs for attribution. Spoofed sources make attribution unreliable.")
            if x["syn"] >= c["ddos_syn"] and x["syn"] >= 5 * max(1, synack_from[dst]):
                emit("SYN_FLOOD", "SYN flood", x["syn"], c["ddos_syn"], len(x["syn_src"]), "SYN : SYN-ACK ratio = %d : %d" % (x["syn"], synack_from[dst]))
            if x["udp"] >= c["ddos_udp"]:
                emit("UDP_FLOOD", "UDP flood", x["udp"], c["ddos_udp"], srcs, "UDP packets: %d" % x["udp"])
            if x["icmp"] >= c["ddos_icmp"]:
                emit("ICMP_FLOOD", "ICMP echo flood", x["icmp"], c["ddos_icmp"], srcs, "Echo requests: %d" % x["icmp"])
            if x["dnsr"] >= c["ddos_dns_amp"] and dnsq_by[dst] * 10 < x["dnsr"]:
                emit("DNS_AMPLIFICATION", "DNS amplification (unsolicited responses)", x["dnsr"], c["ddos_dns_amp"], srcs, "Responses received: %d, queries sent by victim: %d" % (x["dnsr"], dnsq_by[dst]))

    # ---------------------------------------------------------------- DNS: tunneling / DGA
    def dns_rules(self):
        A, c = self.A, self.c
        q = [d for d in A.dns if not d["response"]]
        by_dom = defaultdict(lambda: {"names": set(), "recs": [], "types": Counter()})
        by_src = defaultdict(list)
        for d in q:
            x = by_dom[(d["src"], registered_domain(d["qname"]))]
            x["names"].add(d["qname"]); x["recs"].append(d); x["types"][d["qtype"]] += 1
            by_src[d["src"]].append(d)
        flagged = set()
        for (src, dom), x in by_dom.items():
            subs = [n[: -len(dom) - 1] for n in x["names"] if n != dom]
            if len(subs) < c["dns_unique_subs"]:
                continue
            lens = [len(s.replace(".", "")) for s in subs]
            ent = statistics.mean(D.entropy(s.replace(".", "")) for s in subs)
            txt = (x["types"]["TXT"] + x["types"]["NULL"]) / len(x["recs"])
            avg = statistics.mean(lens)
            if avg >= 16 or ent >= 3.3 or txt >= 0.3:
                sev = "High" if (avg >= 25 and ent >= 3.3) or txt >= 0.5 else "Medium"
                self.add("DNS_TUNNEL", "DNS_TUNNEL", "DNS tunneling indicator: %s" % dom, sev, min(1, 0.5 + len(subs) / 200), src, dom, x["recs"][0]["ts"], x["recs"][-1]["ts"],
                         "%s sent %d queries with %d unique subdomains of %s (avg label %.0f chars, entropy %.2f)." % (src, len(x["recs"]), len(subs), dom, avg, ent),
                         "Threshold: ≥%d unique subdomains under one domain AND (avg label ≥16 chars OR entropy ≥3.3 OR ≥30%% TXT/NULL). Observed avg %.1f, entropy %.2f, TXT/NULL %.0f%%." % (c["dns_unique_subs"], avg, ent, txt * 100),
                         ["Unique subdomains: %d" % len(subs), "Sample: %s" % ", ".join(sorted(subs, key=len)[-3:])[:160], "Query types: %s" % dict(x["types"])], [r["no"] for r in x["recs"][:80]],
                         "Block or sinkhole %s, inspect the host %s for tunneling tools (iodine, dnscat2) and review outbound DNS policy." % (dom, src))
                flagged.add(src)
        for src, recs in by_src.items():   # legacy rules: long/high-entropy labels and DNS volume
            long = [r for r in recs if len(r["qname"]) > c["dns_label_len"] or any(len(l) >= c["dns_label_len"] or (len(l) >= 12 and D.entropy(l) >= c["dns_entropy"]) for l in r["qname"].split("."))]
            if len(long) >= 3 and src not in flagged:
                self.add("DNS_LONG_LABEL", "DNS_TUNNEL", "Unusually long/high-entropy DNS names from %s" % src, "High" if len(long) >= 10 else "Medium", 0.6, src, "", long[0]["ts"], long[-1]["ts"],
                         "%d DNS queries had labels ≥%d chars or entropy ≥%.1f." % (len(long), c["dns_label_len"], c["dns_entropy"]), "Legacy KAYVEE rule: ≥3 long/high-entropy names.",
                         ["Sample: %s" % ", ".join(r["qname"] for r in long[:3])[:200]], [r["no"] for r in long[:80]])
            elif len(recs) >= c["dns_volume"] and src not in flagged:
                self.add("DNS_VOLUME", "DNS_TUNNEL", "High DNS query volume from %s" % src, "Low", 0.3, src, "", recs[0]["ts"], recs[-1]["ts"],
                         "%s issued %d DNS queries." % (src, len(recs)), "Legacy KAYVEE rule: ≥%d DNS queries from one source (often benign)." % c["dns_volume"], ["%d queries, %d unique names" % (len(recs), len({r["qname"] for r in recs}))], [r["no"] for r in recs[:40]])
        nx = defaultdict(list)
        for d in A.dns:
            if d["response"] and d["rcode"] == "NXDOMAIN":
                nx[d["dst"]].append(d)
        for src, v in nx.items():
            names = {r["qname"] for r in v}
            tot = sum(1 for d in A.dns if d["response"] and d["dst"] == src) or len(v)
            if len(names) >= c["dga_nx"] and len(v) / max(tot, 1) >= 0.5:
                self.add("DGA_NXDOMAIN", "DGA", "Possible DGA activity from %s" % src, "Medium", 0.55, src, "", v[0]["ts"], v[-1]["ts"],
                         "%d NXDOMAIN responses for %d distinct names (%.0f%% of answered lookups)." % (len(v), len(names), 100 * len(v) / max(tot, 1)),
                         "Threshold: ≥%d distinct NXDOMAIN names and ≥50%% failure ratio - typical of domain-generation algorithms." % c["dga_nx"], ["Sample: %s" % ", ".join(sorted(names)[:5])], [r["no"] for r in v[:60]],
                         "Investigate the process generating these lookups on %s; check for malware C2 resolution." % src)

    # ---------------------------------------------------------------- exfiltration
    def exfil(self):
        A, c = self.A, self.c
        agg = defaultdict(lambda: {"up": 0, "down": 0, "flows": [], "t0": None, "t1": None})
        for f in A.flow_list:
            if is_local(f["client"]) and is_public(f["server"]) and f["proto"] in ("TCP", "UDP"):
                x = agg[(f["client"], f["server"])]
                x["up"] += f["c_pl"]; x["down"] += f["s_pl"]; x["flows"].append(f)
                x["t0"] = f["start"] if x["t0"] is None else min(x["t0"], f["start"]); x["t1"] = f["end"] if x["t1"] is None else max(x["t1"], f["end"])
        for (cl, sv), x in agg.items():
            ratio = x["up"] / max(1, x["down"])
            if x["up"] >= c["exfil_bytes"] and ratio >= c["exfil_ratio"]:
                mb = x["up"] / 1048576
                self.add("DATA_EXFIL", "EXFIL", "Large outbound transfer: %s → %s" % (cl, sv), "Critical" if mb >= 50 else "High" if mb >= 5 else "Medium", min(1, 0.45 + mb / 40), cl, sv, x["t0"], x["t1"],
                         "%s uploaded %.2f MB to external host %s (upload:download ratio %.0f:1)." % (cl, mb, sv, ratio),
                         "Threshold: ≥%.1f MB payload to one external host and upload ≥%d× download. Observed %.2f MB, ratio %.1f." % (c["exfil_bytes"] / 1048576, c["exfil_ratio"], mb, ratio),
                         ["Uploaded payload: %d bytes" % x["up"], "Downloaded payload: %d bytes" % x["down"], "Flows: %d" % len(x["flows"]), "Services: %s" % ", ".join(sorted({f["app"] or str(f["sport"]) for f in x["flows"]}))],
                         [n for f in x["flows"][:20] for n in f["pkt_nos"][:3]], "Identify the data/process behind this upload, check DLP and proxy logs, and confirm whether %s is an approved destination." % sv)
        icmp = defaultdict(list)
        for p in A.pkts:
            if p.proto == "ICMP" and p.pl >= c["icmp_payload"]:
                icmp[(p.src, p.dst)].append(p)
        for (s, d), ps in icmp.items():
            if len(ps) >= 5:
                self.add("ICMP_TUNNEL", "ICMP_TUNNEL", "Large ICMP payloads %s → %s" % (s, d), "Medium", 0.5, s, d, ps[0].ts, ps[-1].ts, "%d ICMP packets carried ≥%d bytes payload (avg %d)." % (len(ps), c["icmp_payload"], sum(p.pl for p in ps) / len(ps)),
                         "Rule: ≥5 ICMP packets with payload ≥%d bytes (normal ping is 32-64 bytes) - possible ICMP tunnel/exfiltration." % c["icmp_payload"], ["%d packets" % len(ps)], [p.no for p in ps[:60]])

    # ---------------------------------------------------------------- beaconing / suspicious ports
    def beacon(self):
        A, c = self.A, self.c
        groups = defaultdict(list)
        for f in A.flow_list:
            if f["proto"] == "TCP" and f["sport"] not in NO_BEACON_PORTS and (f["syn"] or f["midstream"]):
                groups[(f["client"], f["server"], f["sport"])].append(f)
        for (cl, sv, pt), fl in groups.items():
            if len(fl) < c["beacon_min_conns"]:
                continue
            ts = sorted(f["start"] for f in fl)
            iv = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.05]
            if len(iv) < c["beacon_min_conns"] - 1:
                continue
            m = statistics.mean(iv)
            cv = statistics.pstdev(iv) / m if m else 9
            if 1 <= m <= 3600 and cv <= c["beacon_cv"]:
                tight = cv <= 0.1 and len(fl) >= 15
                self.add("BEACONING", "BEACON", "Periodic connections: %s → %s:%d" % (cl, sv, pt), "High" if tight and is_public(sv) else "Medium", min(1, 0.45 + len(fl) / 60 + (0.1 if tight else 0)), cl, sv, ts[0], ts[-1],
                         "%d connections at a near-constant interval of %.1fs (jitter %.0f%%)." % (len(fl), m, cv * 100),
                         "Threshold: ≥%d connections with coefficient of variation ≤%.2f of the inter-arrival times. Observed mean %.2fs, CV %.3f. Periodicity alone is not proof of malware (updaters/monitoring also beacon)." % (c["beacon_min_conns"], c["beacon_cv"], m, cv),
                         ["Connections: %d" % len(fl), "Mean interval: %.2fs" % m, "Jitter (CV): %.3f" % cv, "Destination %s is %s" % (sv, ip_class(sv))], [n for f in fl[:40] for n in f["pkt_nos"][:2]],
                         "Identify the process on %s making the periodic calls; check %s reputation and the SNI/Host header used." % (cl, sv))
        seen = defaultdict(list)
        for d in A.dns:
            if not d["response"]:
                seen[(d["src"], d["qname"])].append(d["ts"])
        for (src, name), ts in seen.items():
            if len(ts) >= c["beacon_min_conns"] and not name.endswith((".local", ".arpa")):
                iv = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.05]
                if len(iv) >= c["beacon_min_conns"] - 1:
                    m = statistics.mean(iv); cv = statistics.pstdev(iv) / m if m else 9
                    if 1 <= m <= 3600 and cv <= c["beacon_cv"]:
                        self.add("DNS_BEACON", "BEACON", "Periodic DNS lookups for %s" % name, "Medium", 0.5, src, name, ts[0], ts[-1], "%s resolved %s %d times every ~%.1fs." % (src, name, len(ts), m),
                                 "Threshold: ≥%d lookups of one name with CV ≤%.2f. Observed CV %.3f." % (c["beacon_min_conns"], c["beacon_cv"], cv), ["%d lookups" % len(ts)], [r["no"] for r in A.dns if r["src"] == src and r["qname"] == name][:60])
        for f in A.flow_list:
            if f["proto"] == "TCP" and f["synack"] and f["sport"] in SUSPICIOUS_PORTS:
                self.add("SUSPICIOUS_PORT", "SUSPICIOUS_PORT", "Connection to port %d (%s)" % (f["sport"], SUSPICIOUS_PORTS[f["sport"]]), "Low", 0.4, f["client"], f["server"], f["start"], f["end"],
                         "%s connected to %s:%d which is commonly associated with %s." % (f["client"], f["server"], f["sport"], SUSPICIOUS_PORTS[f["sport"]]), "Heuristic: connection completed to a port commonly used by backdoors/C2 frameworks. Many legitimate services can also use these ports.",
                         ["%d bytes uploaded, %d downloaded" % (f["c_pl"], f["s_pl"])], f["pkt_nos"][:40])

    # ---------------------------------------------------------------- IOC / threat intelligence
    def ioc_match(self):
        A = self.A
        if not self.iocs:
            return
        import ipaddress
        ips, nets, doms, ja3, urls = {}, [], {}, {}, []
        for i in self.iocs:
            v, t = i["value"].lower(), i["type"]
            if t == "ip": ips[v] = i
            elif t == "cidr":
                try: nets.append((ipaddress.ip_network(v, strict=False), i))
                except ValueError: pass
            elif t == "domain": doms[v] = i
            elif t == "ja3": ja3[v] = i
            elif t == "url": urls.append((v, i))
        hits = defaultdict(lambda: {"nos": [], "ev": set(), "t": []})

        def note(ioc, key, ev, nos, ts):
            h = hits[(ioc["value"], key)]
            h["ioc"] = ioc; h["ev"].add(ev); h["nos"] += nos; h["t"].append(ts)

        flows_by_ip = defaultdict(list)
        for f in A.flow_list:
            flows_by_ip[f["client"]].append(f); flows_by_ip[f["server"]].append(f)
        for ip in A.hosts:
            m = ips.get(ip)
            if not m and nets and ip_class(ip) in ("public", "private"):
                try:
                    a = ipaddress.ip_address(ip)
                    m = next((i for n, i in nets if a in n), None)
                except ValueError:
                    m = None
            if m:
                fl = flows_by_ip.get(ip, [])
                note(m, ip, "IP %s observed in %d flow(s)" % (ip, len(fl)), [n for f in fl[:20] for n in f["pkt_nos"][:3]], A.hosts[ip]["first"])
        def dom_match(name):
            parts = name.lower().rstrip(".").split(".")
            for k in range(len(parts) - 1):
                m = doms.get(".".join(parts[k:]))
                if m: return m
        for d in A.dns:
            if not d["response"]:
                m = dom_match(d["qname"])
                if m: note(m, d["src"], "DNS query for %s from %s" % (d["qname"], d["src"]), [d["no"]], d["ts"])
        for t in A.http:
            m = dom_match(t["host"].split(":")[0]) if t["host"] else None
            if m: note(m, t["client"], "HTTP Host %s requested by %s" % (t["host"], t["client"]), [], t["ts"])
            for u, i in urls:
                if u in (t["host"] + t["uri"]).lower(): note(i, t["client"], "URL match %s%s" % (t["host"], t["uri"][:80]), [], t["ts"])
        for t in A.tls:
            m = dom_match(t.get("sni", "")) if t.get("sni") else None
            if m: note(m, t["client"], "TLS SNI %s from %s" % (t["sni"], t["client"]), [], t["ts"])
            j = ja3.get(t.get("ja3", ""))
            if j: note(j, t["client"], "TLS client fingerprint JA3 %s from %s" % (t["ja3"], t["client"]), [], t["ts"])
        for (val, key), h in hits.items():
            i = h["ioc"]
            sev = i.get("severity") if i.get("severity") in SEVERITY_SCORE else "High"
            self.add("IOC_MATCH", "IOC", "IOC match: %s (%s)" % (val, i["type"]), sev, 0.9, key if i["type"] != "ip" else "", val if i["type"] == "ip" else "", min(h["t"]), max(h["t"]),
                     "Capture contains traffic matching threat-intelligence indicator %s%s." % (val, (" - " + i["description"]) if i.get("description") else ""),
                     "Exact/suffix match against your loaded IOC list (source: %s)." % (i.get("source") or "manual"), sorted(h["ev"])[:10], h["nos"], "Treat the involved host as potentially compromised; pivot on the matching flows/packets and check other logs for this indicator.", {"ioc_type": i["type"], "ioc_source": i.get("source", "")})

    # ---------------------------------------------------------------- statistical anomalies
    def anomalies(self):
        A, c = self.A, self.c
        if len(A.pkts) >= 20:
            counts = Counter(p.src for p in A.pkts if p.src)
            if len(counts) >= 3:
                vals = list(counts.values()); mean = statistics.mean(vals); sd = statistics.pstdev(vals)
                med = statistics.median(vals); mad = statistics.median([abs(v - med) for v in vals]) or 1
                for ip, n in counts.items():
                    z = (n - mean) / sd if sd else 0
                    if z >= c["z_host"] and n >= 30:
                        self.add("HOST_VOLUME_ANOMALY", "ANOMALY", "Packet-volume outlier: %s" % ip, "Medium", 0.5, ip, "", A.hosts[ip]["first"], A.hosts[ip]["last"],
                                 "%s sent %d packets - a statistical outlier in this capture." % (ip, n), "Legacy KAYVEE rule: z-score ≥%.1f and ≥30 packets. Observed z=%.2f (robust MAD-z %.1f)." % (c["z_host"], z, 0.6745 * (n - med) / mad),
                                 ["%d packets (mean %.1f, σ %.1f)" % (n, mean, sd)], [])
        s = A.series["pkts"]
        if len(s) >= 20:
            m, sd = statistics.mean(s), statistics.pstdev(s)
            if sd > 0:
                spikes = [(i, v) for i, v in enumerate(s) if (v - m) / sd >= c["z_bin"] and v >= 50]
                if spikes:
                    i, v = max(spikes, key=lambda t: t[1])
                    t0 = A.t0 + i * A.bin_s
                    self.add("TRAFFIC_SPIKE", "ANOMALY", "Traffic spike at %s" % _fmt(t0), "Low", 0.4, "", "", t0, t0 + A.bin_s, "Packet rate reached %d packets in one %.1fs bin (mean %.1f)." % (v, A.bin_s, m),
                             "Rule: bin z-score ≥%.1f and ≥50 packets. %d spike bin(s) found." % (c["z_bin"], len(spikes)), ["Peak bin: %d packets" % v], [])

    def cleartext(self):
        groups = defaultdict(list)
        for x in self.A.cleartext:
            groups[(x["client"], x["server"], x["port"], x["kind"])].append(x)
        for (cl, sv, pt, kind), v in groups.items():
            fl = {f["id"]: f for f in self.A.flow_list}
            nos = [n for x in v[:10] for n in fl[x["flow"]]["pkt_nos"][:3]]
            self.add("CLEARTEXT_AUTH", "CLEARTEXT", "Cleartext credentials exposure: %s" % kind.split(" (")[0], "Low", 0.7, cl, sv, min(x["ts"] for x in v), max(x["ts"] for x in v),
                     "%s sent %s to %s:%d without encryption." % (cl, kind, sv, pt), "Observation: authentication material crossed the network in cleartext. Values are deliberately NOT stored by KAYVEE.", ["%d session(s)" % len(v)], nos,
                     "Migrate to an encrypted alternative (HTTPS/SFTP/SSH) and rotate any credentials that crossed this link.")


def _fmt(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%H:%M:%S UTC")


def host_scores(A, alerts):
    """Return {ip: score}. Actors receive full alert score, targets 40%."""
    per = defaultdict(list)
    for a in alerts:
        if a["src"] in A.hosts:
            per[a["src"]].append(a["score"])
        if a["dst"] in A.hosts:
            per[a["dst"]].append(a["score"] * 0.4)
    return {ip: noisy_or(v) for ip, v in per.items()}
