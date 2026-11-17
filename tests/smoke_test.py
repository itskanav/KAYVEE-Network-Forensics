"""End-to-end API smoke test: builds a synthetic lab capture, uploads it and exercises every workflow.
Run:  python tests/smoke_test.py      (uses a throw-away data folder; never touches your real data)"""
import os, sys, time, tempfile, subprocess
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
tmp = tempfile.mkdtemp(prefix="kayvee_test_")
os.environ["KAYVEE_DATA"] = os.path.join(tmp, "data")
sys.path.insert(0, ROOT)
pcap = os.path.join(tmp, "lab.pcap")
subprocess.check_call([sys.executable, os.path.join(ROOT, "tests", "make_test_pcap.py"), pcap], stdout=subprocess.DEVNULL)
import app as K
c = K.app.test_client()

def J(r):
    assert r.status_code < 400, (r.status_code, r.data[:300]); return r.get_json()
def wait(jid):
    for _ in range(600):
        j = J(c.get("/api/jobs/" + jid))
        if j["status"] != "running": return j
        time.sleep(0.1)
    raise AssertionError("job timeout")
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name); 
    if not cond: sys.exit(1)

r = J(c.post("/api/upload", data={"file": (open(pcap, "rb"), "lab.pcap")}, content_type="multipart/form-data")); j = wait(r["job_id"])
check("upload + analysis completes", j["status"] == "done")
aid = j["result"]["analysis_id"]; o = J(c.get(f"/api/analyses/{aid}/overview")); cats = {a["category"] for a in o["alerts"]}
for need in ("PORT_SCAN", "BRUTE_FORCE", "ARP_SPOOF", "DDOS", "DNS_TUNNEL", "EXFIL", "BEACON", "CLEARTEXT", "ICMP_TUNNEL"):
    check("detects " + need, need in cats)
check("packet count is exact", o["summary"]["packets"] == 4350)
check("TLS SNI extracted", any(t.get("sni") == "update.example.org" for t in J(c.get(f"/api/analyses/{aid}/tls"))))
check("HTTP reconstructed", any(t["uri"] == "/index.html" for t in J(c.get(f"/api/analyses/{aid}/http"))))
eid = r["evidence_id"]; check("SHA-256 verifies", wait(J(c.post(f"/api/evidence/{eid}/verify"))["job_id"])["result"]["status"] == "verified")
ev = K.S.one("SELECT stored_path FROM evidence WHERE id=?", (eid,)); open(ev["stored_path"], "ab").write(b"x")
check("tampering is detected", wait(J(c.post(f"/api/evidence/{eid}/verify"))["job_id"])["result"]["status"] == "mismatch")
check("analysis refuses tampered evidence", wait(J(c.post(f"/api/evidence/{eid}/analyze"))["job_id"])["status"] == "error")
print("\nAll checks passed")
