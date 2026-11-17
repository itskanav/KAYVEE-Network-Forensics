"""GeoIP lookup (optional local MaxMind-format database) and IOC / threat-intelligence import. Offline-first."""
import os, re, json, csv, io, ipaddress, time, urllib.request
from .netutil import ip_class

DB_NAMES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb", "GeoIP2-City.mmdb", "city.mmdb")
ASN_NAMES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb", "asn.mmdb")


class Geo:
    def __init__(self, folder):
        self.folder, self.city, self.asn, self.reason, self.cache = folder, None, None, "", {}
        self.reload()

    def reload(self):
        self.city = self.asn = None
        self.cache = {}
        try:
            import maxminddb
        except ImportError:
            self.reason = "Python package 'maxminddb' is not installed (pip install maxminddb)."
            return
        os.makedirs(self.folder, exist_ok=True)
        for n in DB_NAMES:
            p = os.path.join(self.folder, n)
            if os.path.exists(p):
                try:
                    self.city = maxminddb.open_database(p)
                    break
                except Exception as e:
                    self.reason = "Could not open %s: %s" % (n, e)
        for n in ASN_NAMES:
            p = os.path.join(self.folder, n)
            if os.path.exists(p):
                try:
                    self.asn = maxminddb.open_database(p)
                    break
                except Exception:
                    pass
        if not self.city and not self.reason:
            self.reason = "No GeoIP database found. Place GeoLite2-City.mmdb in %s." % self.folder

    @property
    def available(self):
        return self.city is not None

    def status(self):
        return {"available": self.available, "reason": "" if self.available else self.reason, "folder": self.folder, "asn": self.asn is not None}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        out = None
        if self.city and ip_class(ip) == "public":
            try:
                r = self.city.get(ip) or {}
                loc = r.get("location") or {}
                if loc.get("latitude") is not None:
                    out = {"country": (r.get("country") or {}).get("names", {}).get("en", ""), "cc": (r.get("country") or {}).get("iso_code", ""),
                           "city": (r.get("city") or {}).get("names", {}).get("en", ""), "lat": loc["latitude"], "lon": loc["longitude"], "asn": "", "org": ""}
                    if self.asn:
                        a = self.asn.get(ip) or {}
                        out["asn"], out["org"] = a.get("autonomous_system_number", ""), a.get("autonomous_system_organization", "")
            except Exception:
                out = None
        self.cache[ip] = out
        return out


# ------------------------------------------------------------------ IOC import
_HEX32, _HEX64 = re.compile(r"^[a-f0-9]{32}$"), re.compile(r"^[a-f0-9]{64}$")
_DOM = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def classify(v):
    v = v.strip().lower().strip("\"'")
    if not v:
        return None, v
    try:
        ipaddress.ip_address(v); return "ip", v
    except ValueError:
        pass
    if "/" in v and not v.startswith("http"):
        try:
            ipaddress.ip_network(v, strict=False); return "cidr", v
        except ValueError:
            return None, v
    if v.startswith(("http://", "https://")):
        return "url", re.sub(r"^https?://", "", v)
    if _HEX32.match(v):
        return "ja3", v
    if _HEX64.match(v):
        return "sha256", v
    v = v.lstrip("*.")
    if _DOM.match(v):
        return "domain", v
    return None, v


def parse_iocs(text, source="manual", severity="High"):
    """Accepts plain lists (one indicator per line), CSV (indicator,type,severity,description) or JSON. Returns (iocs, skipped)."""
    out, skipped = [], 0
    text = text.strip()
    rows = []
    if text[:1] in "[{":
        try:
            data = json.loads(text)
            data = data if isinstance(data, list) else data.get("indicators", data.get("iocs", []))
            rows = [r if isinstance(r, dict) else {"value": r} for r in data]
        except Exception:
            rows = []
    else:
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith(("#", ";", "//"))]
        if lines and ("," in lines[0]) and re.search(r"indicator|value|ioc|ip|domain", lines[0].lower()) and not classify(lines[0].split(",")[0])[0]:
            rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
            rows = [{(k or "").lower().strip(): v for k, v in r.items()} for r in rows]
            rows = [{"value": r.get("indicator") or r.get("value") or r.get("ioc") or r.get("ip") or r.get("domain") or "", "severity": r.get("severity", ""), "description": r.get("description", "")} for r in rows]
        else:
            rows = [{"value": re.split(r"[,\s;]", l.strip())[0]} for l in lines]
    seen = set()
    for r in rows:
        t, v = classify(str(r.get("value") or r.get("indicator") or ""))
        if not t or t == "sha256" or (t, v) in seen:
            skipped += 1
            continue
        seen.add((t, v))
        sev = str(r.get("severity") or severity).title()
        out.append({"type": t, "value": v, "source": source, "severity": sev if sev in ("Critical", "High", "Medium", "Low") else severity, "description": str(r.get("description") or "")[:200]})
    return out, skipped


def fetch_feed(url, max_bytes=8_000_000):
    """Explicit, user-triggered download of an indicator list. Only the URL is contacted; no capture data is sent."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("Feed URL must start with http:// or https://")
    req = urllib.request.Request(url, headers={"User-Agent": "KAYVEE-Forensics/2.0 (+indicator feed fetch)"})
    with urllib.request.urlopen(req, timeout=25) as r:
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Feed is larger than %d MB" % (max_bytes // 1_000_000))
    return data.decode("utf-8", "replace")
