#!/usr/bin/env python3
"""KAYVEE Network Forensics Platform - local web application.  Run:  python app.py   ->  http://127.0.0.1:5000"""
import os, sys, io, json, gzip, time, uuid, shutil, hashlib, argparse, threading
from collections import OrderedDict
from flask import Flask, request, jsonify, send_from_directory, send_file, abort
from werkzeug.utils import secure_filename

from kayvee import __version__
from kayvee.store import Store
from kayvee.pipeline import Jobs, analyze_evidence
from kayvee.pcapio import iter_packets, PcapError
from kayvee.dissect import dissect
from kayvee.intel import Geo, parse_iocs, fetch_feed
from kayvee.live import LiveCapture, capability
from kayvee import reports as RP, assistant as AS
from kayvee.netutil import sha256_file, ip_class

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.abspath(os.environ.get("KAYVEE_DATA", os.path.join(BASE, "data")))
for d in ("evidence", "analyses", "reports", "geoip"):
    os.makedirs(os.path.join(DATA, d), exist_ok=True)

app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 ** 3
app.json.sort_keys = False
S = Store(os.path.join(DATA, "kayvee.db"))
GEO = Geo(os.path.join(DATA, "geoip"))
JOBS = Jobs()
LIVE = LiveCapture(os.path.join(DATA, "evidence"))
_cache = OrderedDict()
_lock = threading.Lock()
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def analyst():
    return S.get_setting("analyst", "Analyst")


@app.errorhandler(Exception)
def on_error(e):
    code = getattr(e, "code", 500)
    if code == 500:
        app.logger.exception("Unhandled error")
    return jsonify({"error": getattr(e, "description", None) or "%s: %s" % (type(e).__name__, e)}), code if isinstance(code, int) else 500


def result(aid):
    with _lock:
        if aid in _cache:
            _cache.move_to_end(aid)
            return _cache[aid]
    row = S.one("SELECT * FROM analyses WHERE id=? AND status='done'", (aid,))
    if not row or not os.path.exists(row["result_path"] or ""):
        abort(404, "Analysis not found or not finished")
    with gzip.open(row["result_path"], "rt", encoding="utf-8") as f:
        R = json.load(f)
    # live alert triage state always comes from the database
    st = {r["alert_id"]: r["status"] for r in S.q("SELECT alert_id,status FROM alert_status WHERE analysis_id=?", (aid,))}
    for a in R["alerts"]:
        a["status"] = st.get(a["id"], "new")
    with _lock:
        _cache[aid] = R
        while len(_cache) > 3:
            _cache.popitem(last=False)
    return R


def ensure_case(case_id, title="Untitled investigation"):
    if case_id:
        c = S.one("SELECT * FROM cases WHERE id=?", (case_id,))
        if c:
            return c
    return new_case(title)


def new_case(title, description="", priority="Medium"):
    now = time.time()
    cid = S.x("INSERT INTO cases(case_no,title,description,status,priority,analyst,created,updated) VALUES(?,?,?,?,?,?,?,?)", ("TMP-%s" % uuid.uuid4().hex[:6], title, description, "Open", priority, analyst(), now, now))
    no = "CASE-%s-%04d" % (time.strftime("%Y"), cid)
    S.x("UPDATE cases SET case_no=? WHERE id=?", (no, cid))
    S.log(analyst(), "CASE_CREATED", title, cid)
    return S.one("SELECT * FROM cases WHERE id=?", (cid,))


def register_evidence(path, filename, size, digest, source, case, notes="", meta=None):
    now = time.time()
    eid = S.x("INSERT INTO evidence(case_id,filename,stored_path,size,sha256,source,acquired_at,acquired_by,notes,last_verified_at,last_verify_status,meta) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (case["id"], filename, path, size, digest, source, now, analyst(), notes, now, "verified", json.dumps(meta or {})))
    S.custody_add(eid, analyst(), "ACQUIRED", "%s: %s, %d bytes, SHA-256 %s" % (source, filename, size, digest))
    S.log(analyst(), "EVIDENCE_ADDED", "%s (%s)" % (filename, source), case["id"], eid)
    S.x("UPDATE cases SET updated=? WHERE id=?", (now, case["id"]))
    return eid


# ----------------------------------------------------------------------------- pages / status
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/status")
def status():
    return jsonify({"version": __version__, "analyst": analyst(), "geo": GEO.status(), "live": {k: v for k, v in capability().items()}, "iocs": S.one("SELECT COUNT(*) n FROM iocs")["n"],
                    "counts": {"cases": S.one("SELECT COUNT(*) n FROM cases")["n"], "evidence": S.one("SELECT COUNT(*) n FROM evidence")["n"], "analyses": S.one("SELECT COUNT(*) n FROM analyses WHERE status='done'")["n"],
                                "unread": S.one("SELECT COUNT(*) n FROM notifications WHERE read=0")["n"]}, "reportlab": _has("reportlab"), "now": time.time()})


def _has(mod):
    try:
        __import__(mod); return True
    except ImportError:
        return False


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        d = request.get_json(force=True)
        for k in ("analyst", "notify_min_severity", "thresholds"):
            if k in d:
                S.set_setting(k, d[k])
        S.log(analyst(), "SETTINGS_CHANGED", ", ".join(k for k in d))
    from kayvee.detections import DEFAULTS
    return jsonify({"analyst": analyst(), "notify_min_severity": S.get_setting("notify_min_severity", "High"), "thresholds": S.get_setting("thresholds", {}), "threshold_defaults": DEFAULTS})


@app.route("/api/jobs/<jid>")
def job(jid):
    j = JOBS.get(jid)
    return jsonify(j) if j else abort(404, "Unknown job")


# ----------------------------------------------------------------------------- cases
@app.route("/api/cases", methods=["GET", "POST"])
def cases():
    if request.method == "POST":
        d = request.get_json(force=True)
        if not (d.get("title") or "").strip():
            abort(400, "A case title is required")
        return jsonify(new_case(d["title"].strip()[:160], (d.get("description") or "")[:2000], d.get("priority", "Medium")))
    rows = S.q("SELECT c.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) evidence, (SELECT COUNT(*) FROM analyses a WHERE a.case_id=c.id AND a.status='done') analyses, "
               "(SELECT COUNT(*) FROM notes n WHERE n.case_id=c.id) notes FROM cases c ORDER BY updated DESC")
    return jsonify(rows)


@app.route("/api/cases/<int:cid>", methods=["GET", "PATCH"])
def case_detail(cid):
    c = S.one("SELECT * FROM cases WHERE id=?", (cid,)) or abort(404, "Case not found")
    if request.method == "PATCH":
        d = request.get_json(force=True)
        for k in ("status", "priority", "title", "description"):
            if k in d:
                S.x("UPDATE cases SET %s=?, updated=? WHERE id=?" % k, (d[k], time.time(), cid))
        S.log(analyst(), "CASE_UPDATED", json.dumps(d)[:200], cid)
        c = S.one("SELECT * FROM cases WHERE id=?", (cid,))
    c["evidence"] = S.q("SELECT id,filename,size,sha256,source,acquired_at,last_verify_status,last_verified_at FROM evidence WHERE case_id=? ORDER BY id DESC", (cid,))
    c["analyses"] = S.q("SELECT id,evidence_id,created,status,packet_count,summary FROM analyses WHERE case_id=? ORDER BY id DESC", (cid,))
    for a in c["analyses"]:
        a["summary"] = json.loads(a["summary"]) if a["summary"] else None
    c["notes"] = S.q("SELECT * FROM notes WHERE case_id=? ORDER BY ts DESC", (cid,))
    c["history"] = S.q("SELECT * FROM history WHERE case_id=? ORDER BY ts DESC LIMIT 100", (cid,))
    return jsonify(c)


# ----------------------------------------------------------------------------- upload / evidence
@app.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        abort(400, "No file received")
    name = secure_filename(f.filename) or "capture.pcap"
    if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
        abort(400, "Unsupported file type. Upload a .pcap, .pcapng or .cap capture.")
    case = ensure_case(request.form.get("case_id", type=int), name)
    path = os.path.join(DATA, "evidence", "%s_%s" % (uuid.uuid4().hex[:8], name))
    h, size = hashlib.sha256(), 0
    with open(path, "wb") as out:
        while True:
            b = f.stream.read(1 << 20)
            if not b:
                break
            out.write(b); h.update(b); size += len(b)
    with open(path, "rb") as t:
        magic = t.read(4)
    if magic not in (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        os.remove(path)
        abort(400, "The file is not a valid PCAP/PCAPNG capture (unrecognised signature).")
    eid = register_evidence(path, name, size, h.hexdigest(), "upload", case, request.form.get("notes", ""))
    jid = JOBS.start("analysis", analyze_evidence, S, GEO, DATA, eid, analyst()) if request.form.get("analyze", "1") == "1" else None
    return jsonify({"evidence_id": eid, "case_id": case["id"], "sha256": h.hexdigest(), "size": size, "job_id": jid})


@app.route("/api/evidence")
def evidence_list():
    rows = S.q("SELECT e.*, c.case_no FROM evidence e LEFT JOIN cases c ON c.id=e.case_id ORDER BY e.id DESC")
    for r in rows:
        r["chain"] = S.custody_verify(r["id"])
        r["exists"] = os.path.exists(r["stored_path"])
        r["analyses"] = S.q("SELECT id,created,status,packet_count FROM analyses WHERE evidence_id=? ORDER BY id DESC", (r["id"],))
        r.pop("stored_path", None)
    return jsonify(rows)


@app.route("/api/evidence/<int:eid>")
def evidence_detail(eid):
    e = S.one("SELECT e.*, c.case_no FROM evidence e LEFT JOIN cases c ON c.id=e.case_id WHERE e.id=?", (eid,)) or abort(404, "Evidence not found")
    e["custody"] = S.q("SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (eid,))
    e["chain"] = S.custody_verify(eid)
    e["exists"] = os.path.exists(e["stored_path"])
    e["analyses"] = S.q("SELECT id,created,status,packet_count,error FROM analyses WHERE evidence_id=? ORDER BY id DESC", (eid,))
    e.pop("stored_path")
    return jsonify(e)


def _verify(upd, eid, actor):
    e = S.one("SELECT * FROM evidence WHERE id=?", (eid,))
    if not os.path.exists(e["stored_path"]):
        S.x("UPDATE evidence SET last_verify_status='missing', last_verified_at=? WHERE id=?", (time.time(), eid))
        S.custody_add(eid, actor, "INTEGRITY_CHECK", "FAILED - evidence file is missing")
        S.notify("critical", "Evidence file missing", e["filename"], "evidence", eid)
        return {"status": "missing", "expected": e["sha256"], "actual": None}
    upd("Computing SHA-256", 0.0, "Reading %s" % e["filename"])
    d = sha256_file(e["stored_path"], lambda f: upd(progress=f))
    st = "verified" if d == e["sha256"] else "mismatch"
    S.x("UPDATE evidence SET last_verified_at=?, last_verify_status=? WHERE id=?", (time.time(), st, eid))
    S.custody_add(eid, actor, "INTEGRITY_CHECK", "%s - computed %s, recorded %s" % (st.upper(), d, e["sha256"]))
    S.log(actor, "EVIDENCE_VERIFIED", st, e["case_id"], eid)
    if st != "verified":
        S.notify("critical", "Evidence integrity FAILED", "%s differs from its acquisition hash" % e["filename"], "evidence", eid)
    return {"status": st, "expected": e["sha256"], "actual": d}


@app.route("/api/evidence/<int:eid>/verify", methods=["POST"])
def evidence_verify(eid):
    S.one("SELECT 1 x FROM evidence WHERE id=?", (eid,)) or abort(404, "Evidence not found")
    return jsonify({"job_id": JOBS.start("verify", _verify, eid, analyst())})


@app.route("/api/evidence/<int:eid>/analyze", methods=["POST"])
def evidence_analyze(eid):
    S.one("SELECT 1 x FROM evidence WHERE id=?", (eid,)) or abort(404, "Evidence not found")
    return jsonify({"job_id": JOBS.start("analysis", analyze_evidence, S, GEO, DATA, eid, analyst())})


@app.route("/api/evidence/<int:eid>/download")
def evidence_download(eid):
    e = S.one("SELECT * FROM evidence WHERE id=?", (eid,)) or abort(404)
    S.custody_add(eid, analyst(), "EXPORTED", "Original evidence file downloaded")
    return send_file(e["stored_path"], as_attachment=True, download_name=e["filename"])


# ----------------------------------------------------------------------------- analyses
@app.route("/api/analyses")
def analyses():
    rows = S.q("SELECT a.id,a.evidence_id,a.case_id,a.created,a.status,a.error,a.packet_count,a.summary,e.filename,c.case_no FROM analyses a LEFT JOIN evidence e ON e.id=a.evidence_id LEFT JOIN cases c ON c.id=a.case_id ORDER BY a.id DESC")
    for r in rows:
        s = json.loads(r["summary"]) if r["summary"] else None
        r["summary"] = {k: s[k] for k in ("packets", "bytes", "hosts", "alerts", "case_score", "case_level", "duration")} if s else None
    return jsonify(rows)


@app.route("/api/analyses/<int:aid>/overview")
def overview(aid):
    R = result(aid)
    ev = S.one("SELECT * FROM evidence WHERE id=?", (R["evidence_id"],))
    R["summary"]["evidence"].update({"status": ev["last_verify_status"], "verified_at": ev["last_verified_at"], "source": ev["source"]})
    top_flows = sorted(R["flows"], key=lambda f: -(f["c_bytes"] + f["s_bytes"]))[:10]
    return jsonify({"summary": R["summary"], "alerts": R["alerts"], "hosts": R["hosts"][:150], "series": R["series"], "bin_s": R["bin_s"], "t0": R["t0"], "t1": R["t1"], "graph": R["graph"],
                    "timeline": R["timeline"], "recommendations": AS.recommendations(R), "narrative": AS.narrative(R), "dns": {k: v for k, v in R["dns"].items() if k != "records"},
                    "top_flows": top_flows, "ioc_loaded": S.one("SELECT COUNT(*) n FROM iocs")["n"], "geo": GEO.status(), "case_id": R["case_id"]})


@app.route("/api/analyses/<int:aid>/<section>")
def section(aid, section):
    R = result(aid)
    if section not in ("hosts", "flows", "http", "tls", "arp", "cleartext", "alerts", "timeline", "dns"):
        abort(404)
    data = R[section]
    if section == "dns":
        data = dict(data)
        q = request.args.get("q", "").lower()
        recs = [d for d in data["records"] if not q or q in d["qname"] or q in d["src"]]
        data["records"] = recs[:3000]
        data["total_records"] = len(recs)
    elif section == "flows":
        q, proto = request.args.get("q", "").lower(), request.args.get("proto", "")
        data = [f for f in data if (not proto or f["proto"] == proto or f["app"] == proto) and (not q or q in f["client"] or q in f["server"] or q in str(f["sport"]) or q in (f.get("tls_sni") or "").lower())]
        if request.args.get("data") == "1":
            data = [f for f in data if f.get("has_data")]
        data = sorted(data, key=lambda f: -(f["c_bytes"] + f["s_bytes"]))[:3000]
    elif section == "alerts":
        sev, cat = request.args.get("severity"), request.args.get("category")
        data = [a for a in data if (not sev or a["severity"] == sev) and (not cat or a["category"] == cat)]
    return jsonify(data)


@app.route("/api/analyses/<int:aid>/alerts/<alert_id>", methods=["GET", "PATCH"])
def alert_detail(aid, alert_id):
    R = result(aid)
    a = next((a for a in R["alerts"] if a["id"] == alert_id), None) or abort(404, "Alert not found")
    if request.method == "PATCH":
        st = request.get_json(force=True).get("status")
        if st not in ("new", "investigating", "confirmed", "false-positive"):
            abort(400, "Invalid status")
        S.x("INSERT INTO alert_status VALUES(?,?,?,?,?) ON CONFLICT(analysis_id,alert_id) DO UPDATE SET status=excluded.status, updated=excluded.updated, by=excluded.by", (aid, alert_id, st, time.time(), analyst()))
        S.log(analyst(), "ALERT_TRIAGE", "%s → %s" % (alert_id, st), R["case_id"], R["evidence_id"], aid)
        a["status"] = st
    out = dict(a)
    out["packets"] = _packets_by_no(aid, a["packet_nos"][:60])
    out["notes"] = S.q("SELECT * FROM notes WHERE analysis_id=? AND ref=? ORDER BY ts", (aid, alert_id))
    return jsonify(out)


def _packets_by_no(aid, nos):
    if not nos:
        return []
    ph = ",".join("?" * len(nos))
    return S.q("SELECT no,ts,src,dst,proto,sport,dport,len,info FROM packets WHERE analysis_id=? AND no IN (%s) ORDER BY no" % ph, (aid, *nos))


@app.route("/api/analyses/<int:aid>/host/<path:ip>")
def host_detail(aid, ip):
    R = result(aid)
    h = next((h for h in R["hosts"] if h["ip"] == ip), None) or abort(404, "Host not in this analysis")
    out = dict(h)
    out["alert_details"] = [a for a in R["alerts"] if a["id"] in h["alerts"]]
    out["flows"] = sorted([f for f in R["flows"] if f["client"] == ip or f["server"] == ip], key=lambda f: -(f["c_bytes"] + f["s_bytes"]))[:200]
    out["peers_detail"] = sorted([e for e in R["graph"]["edges"] if e["s"] == ip or e["d"] == ip], key=lambda e: -e["bytes"])[:40]
    out["dns"] = [d for d in R["dns"]["records"] if d["src"] == ip and not d["response"]][:100]
    out["tls"] = [t for t in R["tls"] if t["client"] == ip][:50]
    out["http"] = [t for t in R["http"] if t["client"] == ip or t["server"] == ip][:50]
    out["notes"] = S.q("SELECT * FROM notes WHERE analysis_id=? AND ref=? ORDER BY ts", (aid, ip))
    out["ip_notes"] = {"private": "RFC1918/ULA private address - not geolocatable.", "public": "" if h["geo"] else "Public address - GeoIP database not loaded or no record for this address."}.get(h["class"], "Special-purpose address (%s)." % h["class"])
    return jsonify(out)


@app.route("/api/analyses/<int:aid>/pair")
def pair(aid):
    R = result(aid)
    a, b = request.args.get("a", ""), request.args.get("b", "")
    fl = [f for f in R["flows"] if {f["client"], f["server"]} == {a, b}]
    ed = [e for e in R["graph"]["edges"] if {e["s"], e["d"]} == {a, b}]
    nos = sorted({n for f in fl for n in f["pkt_nos"]})[:80]
    return jsonify({"a": a, "b": b, "flows": fl[:300], "edges": ed, "packets": _packets_by_no(aid, nos)})


@app.route("/api/analyses/<int:aid>/streams/<int:fid>")
def stream(aid, fid):
    R = result(aid)
    f = next((f for f in R["flows"] if f["id"] == fid), None) or abort(404, "Flow not found")
    row = S.one("SELECT result_path FROM analyses WHERE id=?", (aid,))
    with gzip.open(row["result_path"].replace(".json.gz", ".streams.json.gz"), "rt") as fh:
        data = json.load(fh).get(str(fid), {"c": "", "s": "", "c_total": 0, "s_total": 0})
    return jsonify({"flow": f, "data": data, "http": [t for t in R["http"] if t["flow"] == fid], "tls": [t for t in R["tls"] if t["flow"] == fid], "packets": _packets_by_no(aid, f["pkt_nos"][:80])})


@app.route("/api/analyses/<int:aid>/packets")
def packets(aid):
    S.one("SELECT 1 x FROM analyses WHERE id=? AND status='done'", (aid,)) or abort(404)
    w, a = ["analysis_id=?"], [aid]
    q, proto, ip = request.args.get("q", "").strip(), request.args.get("proto", ""), request.args.get("ip", "")
    if q:
        w.append("(src LIKE ? OR dst LIKE ? OR info LIKE ? OR proto LIKE ? OR CAST(sport AS TEXT)=? OR CAST(dport AS TEXT)=? OR CAST(no AS TEXT)=?)"); a += ["%" + q + "%"] * 4 + [q] * 3
    if proto:
        w.append("proto=?"); a.append(proto)
    if ip:
        w.append("(src=? OR dst=?)"); a += [ip, ip]
    page, size = request.args.get("page", 0, type=int), min(request.args.get("size", 100, type=int), 500)
    where = " AND ".join(w)
    total = S.one("SELECT COUNT(*) n FROM packets WHERE " + where, a)["n"]
    rows = S.q("SELECT no,ts,src,dst,proto,sport,dport,len,info FROM packets WHERE %s ORDER BY no LIMIT ? OFFSET ?" % where, a + [size, page * size])
    return jsonify({"total": total, "page": page, "size": size, "rows": rows})


@app.route("/api/analyses/<int:aid>/packets/<int:no>")
def packet_detail(aid, no):
    a = S.one("SELECT a.*, e.stored_path FROM analyses a JOIN evidence e ON e.id=a.evidence_id WHERE a.id=?", (aid,)) or abort(404)
    for i, (ts, link, data, orig) in enumerate(iter_packets(a["stored_path"]), 1):
        if i == no:
            pk = dissect(no, ts, link, data, orig)
            pay = pk.pop("payload", b"")
            lines = []
            for o in range(0, min(len(data), 1024), 16):
                ch = data[o:o + 16]
                lines.append({"off": "%04x" % o, "hex": " ".join("%02x" % c for c in ch), "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in ch)})
            pk["payload_preview"] = "".join(chr(c) if 32 <= c < 127 or c in (10, 13) else "." for c in pay[:600])
            return jsonify({"packet": pk, "hexdump": lines, "frame_len": len(data), "link": link})
    abort(404, "Packet number out of range")


@app.route("/api/analyses/<int:aid>/ask", methods=["POST"])
def ask(aid):
    R = result(aid)
    q = (request.get_json(force=True).get("q") or "")[:400]
    S.log(analyst(), "ASSISTANT_QUERY", q[:120], R["case_id"], R["evidence_id"], aid)
    return jsonify(AS.answer(q, R))


# ----------------------------------------------------------------------------- notes / history / notifications
@app.route("/api/notes", methods=["GET", "POST"])
def notes():
    if request.method == "POST":
        d = request.get_json(force=True)
        if not (d.get("text") or "").strip():
            abort(400, "Note text is empty")
        nid = S.x("INSERT INTO notes(case_id,analysis_id,ref,author,text,ts) VALUES(?,?,?,?,?,?)", (d.get("case_id"), d.get("analysis_id"), d.get("ref", ""), analyst(), d["text"].strip()[:4000], time.time()))
        S.log(analyst(), "NOTE_ADDED", (d.get("ref") or "case") + ": " + d["text"][:80], d.get("case_id"), None, d.get("analysis_id"))
        return jsonify(S.one("SELECT * FROM notes WHERE id=?", (nid,)))
    w, a = [], []
    for k in ("case_id", "analysis_id", "ref"):
        if request.args.get(k):
            w.append(k + "=?"); a.append(request.args[k])
    return jsonify(S.q("SELECT * FROM notes %s ORDER BY ts DESC LIMIT 500" % (("WHERE " + " AND ".join(w)) if w else ""), a))


@app.route("/api/history")
def history():
    cid = request.args.get("case_id", type=int)
    return jsonify(S.q("SELECT h.*, c.case_no FROM history h LEFT JOIN cases c ON c.id=h.case_id %s ORDER BY h.ts DESC LIMIT 300" % ("WHERE h.case_id=%d" % cid if cid else "")))


@app.route("/api/notifications", methods=["GET", "POST"])
def notifications():
    if request.method == "POST":
        S.x("UPDATE notifications SET read=1")
    return jsonify(S.q("SELECT * FROM notifications ORDER BY ts DESC LIMIT 100"))


# ----------------------------------------------------------------------------- threat intelligence
@app.route("/api/iocs", methods=["GET", "POST", "DELETE"])
def iocs():
    if request.method == "POST":
        d = request.get_json(force=True)
        items, skipped = parse_iocs(d.get("text", ""), d.get("source") or "manual", d.get("severity", "High"))
        added = 0
        for i in items:
            try:
                S.x("INSERT INTO iocs(type,value,source,severity,description,added) VALUES(?,?,?,?,?,?)", (i["type"], i["value"], i["source"], i["severity"], i["description"], time.time())); added += 1
            except Exception:
                skipped += 1
        S.log(analyst(), "IOC_IMPORT", "%d added, %d skipped (%s)" % (added, skipped, d.get("source", "manual")))
        return jsonify({"added": added, "skipped": skipped})
    if request.method == "DELETE":
        S.x("DELETE FROM iocs"); S.log(analyst(), "IOC_CLEARED"); return jsonify({"ok": True})
    return jsonify({"items": S.q("SELECT * FROM iocs ORDER BY id DESC LIMIT 1000"), "total": S.one("SELECT COUNT(*) n FROM iocs")["n"], "by_type": {r["type"]: r["n"] for r in S.q("SELECT type, COUNT(*) n FROM iocs GROUP BY type")}})


@app.route("/api/iocs/<int:iid>", methods=["DELETE"])
def ioc_delete(iid):
    S.x("DELETE FROM iocs WHERE id=?", (iid,)); return jsonify({"ok": True})


@app.route("/api/iocs/feed", methods=["POST"])
def ioc_feed():
    d = request.get_json(force=True)
    try:
        text = fetch_feed(d.get("url", ""))
    except Exception as e:
        abort(502, "Could not fetch feed: %s" % e)
    items, skipped = parse_iocs(text, d.get("url", "")[:80], d.get("severity", "High"))
    added = 0
    for i in items:
        try:
            S.x("INSERT INTO iocs(type,value,source,severity,description,added) VALUES(?,?,?,?,?,?)", (i["type"], i["value"], i["source"], i["severity"], i["description"], time.time())); added += 1
        except Exception:
            skipped += 1
    S.log(analyst(), "IOC_FEED", "%s: %d added" % (d.get("url"), added))
    return jsonify({"added": added, "skipped": skipped})


@app.route("/api/geo/reload", methods=["POST"])
def geo_reload():
    GEO.reload(); return jsonify(GEO.status())


# ----------------------------------------------------------------------------- live capture
@app.route("/api/live/status")
def live_status():
    return jsonify({"capability": capability(), "session": LIVE.snapshot()})


@app.route("/api/live/start", methods=["POST"])
def live_start():
    d = request.get_json(force=True)
    try:
        LIVE.start(d.get("iface", ""), d.get("max_seconds", 0), d.get("max_packets", 0))
    except (RuntimeError, ValueError) as e:
        abort(400, str(e))
    S.log(analyst(), "LIVE_CAPTURE_START", d.get("iface", ""))
    return jsonify(LIVE.snapshot())


def _finish_live(snapshot_only=False, case_id=None):
    path = LIVE.path
    if snapshot_only:
        LIVE.writer.flush()
        dst = path.replace(".pcap", "_snapshot_%s.pcap" % time.strftime("%H%M%S"))
        shutil.copyfile(path, dst); path = dst
    if not path or not os.path.exists(path) or os.path.getsize(path) <= 24:
        abort(400, "No packets were captured yet")
    case = ensure_case(case_id, "Live capture %s" % LIVE.iface)
    digest = sha256_file(path)
    eid = register_evidence(path, os.path.basename(path), os.path.getsize(path), digest, "live-capture", case, "Interface %s, backend %s%s" % (LIVE.iface, LIVE.backend, ", snapshot of running capture" if snapshot_only else ""),
                            {"iface": LIVE.iface, "packets": LIVE.packets, "started": LIVE.started})
    return eid, case


@app.route("/api/live/stop", methods=["POST"])
def live_stop():
    if not LIVE.thread:
        abort(400, "No capture session")
    if LIVE.running:
        LIVE.stop()
    S.log(analyst(), "LIVE_CAPTURE_STOP", "%d packets" % LIVE.packets)
    if LIVE.packets == 0:
        return jsonify({"evidence_id": None, "message": "Capture stopped - no packets were received on %s." % LIVE.iface})
    if getattr(LIVE, "_saved", None) == LIVE.path:
        abort(400, "This capture was already saved as evidence")
    eid, case = _finish_live()
    LIVE._saved = LIVE.path
    jid = JOBS.start("analysis", analyze_evidence, S, GEO, DATA, eid, analyst()) if (request.get_json(silent=True) or {}).get("analyze", True) else None
    return jsonify({"evidence_id": eid, "case_id": case["id"], "job_id": jid})


@app.route("/api/live/snapshot", methods=["POST"])
def live_snapshot():
    if not LIVE.running:
        abort(400, "No capture is running")
    eid, case = _finish_live(snapshot_only=True)
    return jsonify({"evidence_id": eid, "case_id": case["id"], "job_id": JOBS.start("analysis", analyze_evidence, S, GEO, DATA, eid, analyst())})


# ----------------------------------------------------------------------------- reports
def _make_report(upd, aid, fmt, dataset):
    R = result(aid)
    case = S.one("SELECT * FROM cases WHERE id=?", (R["case_id"],))
    ev = S.one("SELECT * FROM evidence WHERE id=?", (R["evidence_id"],))
    upd("Collecting evidence record", 0.1); time.sleep(0.25)
    custody = S.q("SELECT ts,actor,action,details,entry_hash FROM custody WHERE evidence_id=? ORDER BY id", (ev["id"],))
    upd("Gathering analyst notes", 0.3); time.sleep(0.2)
    notes_ = S.q("SELECT author,text,ts,ref FROM notes WHERE case_id=? ORDER BY ts", (case["id"],))
    upd("Compiling findings and timeline", 0.5); time.sleep(0.25)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = "KAYVEE_%s_%s" % (case["case_no"], stamp)
    if fmt == "pdf":
        if not _has("reportlab"):
            raise RuntimeError("PDF export needs the 'reportlab' package (pip install reportlab). JSON and CSV export still work.")
        fn = base + ".pdf"; path = os.path.join(DATA, "reports", fn)
        upd("Rendering PDF pages", 0.7)
        RP.pdf_report(path, R, case, ev, custody, notes_, analyst(), bool(S.iocs()))
    elif fmt == "json":
        fn = base + ".json"; path = os.path.join(DATA, "reports", fn)
        upd("Serialising JSON", 0.7)
        open(path, "wb").write(RP.json_report(R, case, ev, custody, notes_, analyst()))
    elif fmt == "csv":
        fn = "%s_%s.csv" % (base, dataset); path = os.path.join(DATA, "reports", fn)
        upd("Writing CSV (%s)" % dataset, 0.7)
        open(path, "wb").write(RP.csv_report(R, dataset))
    else:
        raise ValueError("Unknown format")
    upd("Sealing report with SHA-256", 0.92); time.sleep(0.2)
    digest, size = sha256_file(path), os.path.getsize(path)
    rid = S.x("INSERT INTO reports(case_id,analysis_id,format,filename,path,sha256,size,created,analyst) VALUES(?,?,?,?,?,?,?,?,?)", (case["id"], aid, fmt if fmt != "csv" else "csv:" + dataset, fn, path, digest, size, time.time(), analyst()))
    S.custody_add(ev["id"], analyst(), "REPORT_GENERATED", "%s SHA-256 %s" % (fn, digest))
    S.log(analyst(), "REPORT_GENERATED", fn, case["id"], ev["id"], aid)
    return {"report_id": rid, "filename": fn, "sha256": digest, "size": size}


@app.route("/api/reports", methods=["GET", "POST"])
def reports():
    if request.method == "POST":
        d = request.get_json(force=True)
        result(int(d["analysis_id"]))
        return jsonify({"job_id": JOBS.start("report", _make_report, int(d["analysis_id"]), d.get("format", "pdf"), d.get("dataset", "alerts"))})
    return jsonify(S.q("SELECT r.id,r.case_id,r.analysis_id,r.format,r.filename,r.sha256,r.size,r.created,r.analyst,c.case_no FROM reports r LEFT JOIN cases c ON c.id=r.case_id ORDER BY r.id DESC"))


@app.route("/api/reports/<int:rid>/download")
def report_download(rid):
    r = S.one("SELECT * FROM reports WHERE id=?", (rid,)) or abort(404)
    return send_file(r["path"], as_attachment=True, download_name=r["filename"])


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="KAYVEE Network Forensics Platform")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1 - local only)")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    print("KAYVEE %s  ->  http://%s:%d   (data: %s)" % (__version__, a.host, a.port, DATA))
    app.run(host=a.host, port=a.port, threaded=True, debug=False)
