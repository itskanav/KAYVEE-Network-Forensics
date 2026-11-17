"""Orchestrates evidence verification -> parsing -> detection -> scoring -> persistence, and tracks background jobs."""
import os, json, gzip, time, uuid, threading, traceback
from collections import Counter, defaultdict
from .analyze import Analyzer, MAX_PACKETS
from .detections import Engine, host_scores
from .netutil import level_for, noisy_or, ip_class, sha256_file, is_local


class Jobs:
    def __init__(self):
        self.jobs, self.lock = {}, threading.Lock()

    def start(self, kind, fn, *args):
        jid = uuid.uuid4().hex[:12]
        job = {"id": jid, "kind": kind, "status": "running", "stage": "Queued", "progress": 0.0, "message": "", "result": None, "error": None, "created": time.time()}
        with self.lock:
            self.jobs[jid] = job
            if len(self.jobs) > 200:
                for k in sorted(self.jobs, key=lambda k: self.jobs[k]["created"])[:50]:
                    self.jobs.pop(k, None)

        def upd(stage=None, progress=None, message=None):
            if stage is not None: job["stage"] = stage
            if progress is not None: job["progress"] = round(min(1.0, max(0.0, progress)), 4)
            if message is not None: job["message"] = message

        def runner():
            try:
                job["result"] = fn(upd, *args)
                job["status"], job["progress"], job["stage"] = "done", 1.0, "Complete"
            except Exception as e:
                job["status"], job["error"], job["stage"] = "error", "%s: %s" % (type(e).__name__, e), "Failed"
                job["trace"] = traceback.format_exc()[-1500:]
        threading.Thread(target=runner, daemon=True).start()
        return jid

    def get(self, jid):
        j = self.jobs.get(jid)
        return {k: v for k, v in j.items() if k != "trace"} if j else None


def _jsonable(o):
    if isinstance(o, (set, tuple)):
        return list(o)
    raise TypeError(type(o))


def analyze_evidence(upd, S, geo, data_dir, evidence_id, actor):
    ev = S.one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
    if not ev:
        raise ValueError("Evidence record not found")
    if not os.path.exists(ev["stored_path"]):
        S.x("UPDATE evidence SET last_verify_status='missing' WHERE id=?", (evidence_id,))
        S.notify("critical", "Evidence file missing", ev["filename"], "evidence", evidence_id)
        raise FileNotFoundError("Evidence file is missing from storage: %s" % ev["filename"])
    upd("Verifying SHA-256 before analysis", 0.0)
    digest = sha256_file(ev["stored_path"], lambda f: upd(progress=f * 0.15))
    status = "verified" if digest == ev["sha256"] else "mismatch"
    S.x("UPDATE evidence SET last_verified_at=?, last_verify_status=? WHERE id=?", (time.time(), status, evidence_id))
    S.custody_add(evidence_id, actor, "INTEGRITY_CHECK", "Pre-analysis SHA-256 %s (%s)" % (status.upper(), digest))
    if status != "verified":
        S.notify("critical", "Evidence integrity FAILED", "%s no longer matches its acquisition hash. Analysis aborted." % ev["filename"], "evidence", evidence_id)
        raise ValueError("Evidence hash mismatch - file changed since acquisition. Analysis aborted.")
    aid = S.x("INSERT INTO analyses(evidence_id,case_id,created,status) VALUES(?,?,?,'running')", (evidence_id, ev["case_id"], time.time()))
    try:
        upd("Parsing packets", 0.15)
        A = Analyzer(geo, progress=lambda f: upd(progress=0.15 + f * 0.5)).run(ev["stored_path"])
        if A.total == 0:
            raise ValueError("The capture contains no readable packets.")
        upd("Running detection rules", 0.68)
        cfg = S.get_setting("thresholds", {}) or {}
        alerts = Engine(A, S.iocs(), cfg).run()
        upd("Scoring and building timeline", 0.8)
        result = build_result(A, alerts, geo, ev, aid, S)
        upd("Saving analysis", 0.88)
        rows = [(aid,) + r for r in A.rows]
        S.many("INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        rp = os.path.join(data_dir, "analyses", "%d.json.gz" % aid)
        os.makedirs(os.path.dirname(rp), exist_ok=True)
        with gzip.open(rp, "wt", encoding="utf-8") as f:
            json.dump(result, f, default=_jsonable)
        with gzip.open(rp.replace(".json.gz", ".streams.json.gz"), "wt", encoding="utf-8") as f:
            json.dump(A.stream_data, f)
        summ = result["summary"]
        S.x("UPDATE analyses SET status='done', summary=?, result_path=?, packet_count=? WHERE id=?", (json.dumps(summ), rp, A.total, aid))
        S.custody_add(evidence_id, actor, "ANALYZED", "Analysis #%d: %d packets, %d alerts, case score %d" % (aid, A.total, len(alerts), summ["case_score"]))
        S.log(actor, "ANALYSIS_COMPLETE", "%d packets, %d alerts" % (A.total, len(alerts)), ev["case_id"], evidence_id, aid)
        _notify(S, aid, ev, alerts, summ)
        return {"analysis_id": aid, "evidence_id": evidence_id}
    except Exception as e:
        S.x("UPDATE analyses SET status='error', error=? WHERE id=?", (str(e), aid))
        S.notify("high", "Analysis failed", "%s: %s" % (ev["filename"], e), "analysis", aid, aid)
        raise


def _notify(S, aid, ev, alerts, summ):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    mn = S.get_setting("notify_min_severity", "High")
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    sent = 0
    for a in alerts:
        if rank.get(a["severity"], 0) >= rank.get(mn, 3) and sent < 12:
            S.notify(a["severity"].lower() if a["severity"] != "Info" else "low", a["title"], a["description"], "alert", a["id"], aid)
            sent += 1
    S.notify("info", "Analysis complete: %s" % ev["filename"], "%d packets · %d indicators · case threat score %d (%s)" % (summ["packets"], summ["alerts"], summ["case_score"], summ["case_level"]), "analysis", aid, aid)


def build_result(A, alerts, geo, ev, aid, S):
    scores = host_scores(A, alerts)
    names = defaultdict(set)
    for n, ips in A.resolved.items():
        for ip in ips:
            names[ip].add(n)
    alert_by_host = defaultdict(list)
    for a in alerts:
        for k in (a["src"], a["dst"]):
            if k in A.hosts:
                alert_by_host[k].append(a["id"])
    hosts = []
    for ip, h in A.hosts.items():
        g = geo.lookup(ip) if geo else None
        sc = scores.get(ip, 0)
        srv = [(p, n) for p, n in h["server_ports"].items() if p and n]
        role = "server" if srv and h["pkts_in"] >= h["pkts_out"] else "client" if h["pkts_out"] > 0 else "peer"
        hosts.append({"ip": ip, "class": h["class"], "pkts_out": h["pkts_out"], "pkts_in": h["pkts_in"], "bytes_out": h["bytes_out"], "bytes_in": h["bytes_in"],
                      "first": h["first"], "last": h["last"], "macs": sorted(h["macs"])[:6], "protos": dict(h["protos"].most_common(8)), "ttls": dict(h["ttls"].most_common(4)),
                      "services": [{"port": p, "flows": n} for p, n in sorted(srv, key=lambda x: -x[1])[:10]], "peers": len(h["peers"]), "names": sorted(names.get(ip, []))[:6],
                      "dns_queries": h["dns_queries"], "geo": g, "score": sc, "level": level_for(sc), "alerts": alert_by_host.get(ip, []), "role": role})
    hosts.sort(key=lambda h: -(h["bytes_in"] + h["bytes_out"]))
    flows, keep = [], sorted(A.flow_list, key=lambda f: -(f["c_bytes"] + f["s_bytes"]))[:20000]
    for f in sorted(keep, key=lambda f: f["start"]):
        d = dict(f); d["pkt_nos"] = f["pkt_nos"][:60]; d["has_data"] = f["id"] in A.stream_data
        flows.append(d)
    # DNS summary
    q = [d for d in A.dns if not d["response"]]
    dom_counts = Counter()
    from .netutil import registered_domain
    for d in q:
        dom_counts[registered_domain(d["qname"])] += 1
    nx = sum(1 for d in A.dns if d["response"] and d["rcode"] == "NXDOMAIN")
    dns = {"queries": len(q), "responses": len(A.dns) - len(q), "nxdomain": nx, "unique_names": len({d["qname"] for d in q}), "top_domains": dom_counts.most_common(25),
           "qtypes": dict(Counter(d["qtype"] for d in q).most_common(10)), "resolvers": dict(Counter(d["dst"] for d in q).most_common(8)), "records": A.dns[:20000]}
    # graph
    esc = Counter()
    for a in alerts:
        for k in (a["src"], a["dst"]):
            esc[k] += 1
    pick = {h["ip"] for h in hosts[:100]} | {k for k in esc if k in A.hosts}
    hb = {h["ip"]: h for h in hosts}
    nodes = [{"ip": ip, "class": hb[ip]["class"], "bytes": hb[ip]["bytes_in"] + hb[ip]["bytes_out"], "score": hb[ip]["score"], "level": hb[ip]["level"], "geo": hb[ip]["geo"], "name": (hb[ip]["names"] or [""])[0]} for ip in pick if ip in hb]
    edges = [{"s": s, "d": d, "pkts": e["pkts"], "bytes": e["bytes"], "protos": dict(e["protos"].most_common(3)), "first": e["first"], "last": e["last"]} for (s, d), e in sorted(A.edges.items(), key=lambda kv: -kv[1]["bytes"]) if s in pick and d in pick][:500]
    # alerts: status + sort
    st = {r["alert_id"]: r["status"] for r in S.q("SELECT alert_id,status FROM alert_status WHERE analysis_id=?", (aid,))}
    for a in alerts:
        a["status"] = st.get(a["id"], "new")
    # timeline
    events = [{"ts": a["ts_start"] or A.t0, "end": a["ts_end"], "kind": a["category"], "title": a["title"], "severity": a["severity"], "alert": a["id"], "src": a["src"], "dst": a["dst"], "packet_nos": a["packet_nos"][:60]} for a in alerts]
    events.append({"ts": A.t0, "end": None, "kind": "CAPTURE", "title": "Capture begins", "severity": "Info", "alert": "", "src": "", "dst": "", "packet_nos": [1]})
    events.append({"ts": A.t1, "end": None, "kind": "CAPTURE", "title": "Capture ends", "severity": "Info", "alert": "", "src": "", "dst": "", "packet_nos": [A.total]})
    events.sort(key=lambda e: e["ts"] or 0)
    for i, e in enumerate(events):
        e["idx"] = i
    case_score = noisy_or(sorted((a["score"] for a in alerts), reverse=True)[:6])
    sev_counts = Counter(a["severity"] for a in alerts)
    apps = Counter(f["app"] or "unknown" for f in A.flow_list)
    dur = (A.t1 or 0) - (A.t0 or 0)
    notes = []
    if A.truncated:
        notes.append("Capture exceeds the %d-packet in-memory limit; only the first %d packets were analysed." % (MAX_PACKETS, MAX_PACKETS))
    if A.skipped:
        notes.append("%d packets carry no IP/ARP layer (e.g. STP, LLDP, raw 802.11) and are listed but not attributed to hosts." % A.skipped)
    if geo is None or not geo.available:
        notes.append("GeoIP database not loaded: public IP locations are unavailable (nothing is guessed).")
    if not S.iocs():
        notes.append("No IOC / threat-intelligence list is loaded, so no indicator matching was performed.")
    notes.append("HTTPS payloads are not decrypted; only TLS handshake metadata (SNI, JA3, versions) is extracted.")
    summary = {"packets": A.total, "bytes": A.bytes, "duration": round(dur, 3), "t0": A.t0, "t1": A.t1, "hosts": len(A.hosts), "flows": len(A.flow_list), "streams": len(A.stream_data),
               "alerts": len(alerts), "alerts_by_severity": dict(sev_counts), "protocols": dict(A.protos.most_common()), "apps": dict(apps.most_common(12)),
               "suspicious_connections": len({(a["src"], a["dst"]) for a in alerts if a["src"] in A.hosts and a["dst"] in A.hosts}),
               "dns_queries": len(q), "http_requests": len(A.http), "tls_handshakes": len(A.tls), "arp_packets": len(A.arp),
               "case_score": case_score, "case_level": level_for(case_score), "evidence": {"id": ev["id"], "filename": ev["filename"], "sha256": ev["sha256"], "size": ev["size"], "status": "verified"},
               "link_types": dict(A.links), "host_classes": dict(Counter(h["class"] for h in A.hosts.values())), "notes": notes, "bin_seconds": A.bin_s, "truncated": A.truncated}
    return {"analysis_id": aid, "evidence_id": ev["id"], "case_id": ev["case_id"], "created": time.time(), "summary": summary, "hosts": hosts[:5000], "flows": flows, "dns": dns,
            "http": A.http[:5000], "tls": A.tls[:5000], "arp": A.arp[:5000], "cleartext": A.cleartext[:500], "alerts": alerts, "timeline": events, "graph": {"nodes": nodes, "edges": edges},
            "series": A.series, "bin_s": A.bin_s, "t0": A.t0, "t1": A.t1}
