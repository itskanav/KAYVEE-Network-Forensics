"""Shared helpers: IP classification, domain handling, severity and MITRE mapping."""
import ipaddress, math, hashlib

_cache = {}


def ip_class(ip):
    """private | loopback | link-local | multicast | broadcast | reserved | public | unknown"""
    if not ip:
        return "unknown"
    c = _cache.get(ip)
    if c:
        return c
    try:
        a = ipaddress.ip_address(ip)
        if a.is_loopback:
            c = "loopback"
        elif a.is_multicast:
            c = "multicast"
        elif a.is_link_local:
            c = "link-local"
        elif ip == "255.255.255.255":
            c = "broadcast"
        elif a.is_private and not a.is_global:
            c = "private"
        elif a.is_reserved or a.is_unspecified:
            c = "reserved"
        else:
            c = "public"
    except ValueError:
        c = "unknown"
    if len(_cache) < 200000:
        _cache[ip] = c
    return c


def is_local(ip):
    return ip_class(ip) in ("private", "loopback", "link-local")


def is_public(ip):
    return ip_class(ip) == "public"


SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne"}


def registered_domain(name):
    parts = [p for p in name.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in SLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEVERITY_SCORE = {"Critical": 92, "High": 74, "Medium": 48, "Low": 22, "Info": 5}


def level_for(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def noisy_or(scores):
    p = 1.0
    for s in scores:
        p *= 1 - min(max(s, 0), 100) / 100 * 0.9
    return round((1 - p) * 100)


MITRE = {
    "PORT_SCAN": ("T1046", "Network Service Discovery"),
    "BRUTE_FORCE": ("T1110", "Brute Force"),
    "ARP_SPOOF": ("T1557.002", "ARP Cache Poisoning"),
    "IP_SPOOF": ("T1036", "Masquerading (spoofed source indicators)"),
    "DDOS": ("T1498", "Network Denial of Service"),
    "DNS_TUNNEL": ("T1071.004", "Application Layer Protocol: DNS"),
    "EXFIL": ("T1048", "Exfiltration Over Alternative Protocol"),
    "BEACON": ("T1071", "Application Layer Protocol (C2 beaconing)"),
    "IOC": ("T1071", "Known-bad indicator communication"),
    "ANOMALY": ("", "Statistical anomaly"),
    "CLEARTEXT": ("T1040", "Network Sniffing exposure (cleartext protocol)"),
    "ICMP_TUNNEL": ("T1095", "Non-Application Layer Protocol"),
    "DGA": ("T1568.002", "Dynamic Resolution: DGA"),
    "SUSPICIOUS_PORT": ("T1571", "Non-Standard Port"),
}


def human_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024


def sha256_file(path, progress=None, chunk=1 << 20):
    import os
    h, size, done = hashlib.sha256(), max(1, os.path.getsize(path)), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress:
                progress(done / size)
    return h.hexdigest()
