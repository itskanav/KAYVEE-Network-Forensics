"""Layer 2-4 packet dissector plus DNS / ARP / TLS / HTTP helpers. Pure Python, tolerant of malformed data."""
import struct, socket, hashlib, math, re
from collections import Counter

ETH_IPV4, ETH_ARP, ETH_IPV6 = 0x0800, 0x0806, 0x86DD
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 1, 2, 4, 8, 16
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 10: "NULL", 255: "ANY", 65: "HTTPS", 99: "SPF"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
            135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
            587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5060: "sip",
            5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb", 5353: "mdns", 1900: "ssdp"}


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def mac(b):
    return ":".join("%02x" % x for x in b)


def ip4(b):
    return socket.inet_ntoa(bytes(b))


def ip6(b):
    return socket.inet_ntop(socket.AF_INET6, bytes(b))


# --------------------------------------------------------------------------- DNS
def _dns_name(msg, off, depth=0):
    labels, jumped, end = [], False, off
    while depth < 40:
        if off >= len(msg):
            raise ValueError("dns name overrun")
        ln = msg[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            off, jumped, depth = ptr, True, depth + 1
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
        depth += 1
        if not jumped:
            end = off
    return ".".join(labels), end


def parse_dns(p):
    if len(p) < 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", p[:12])
    if qd < 1 or qd > 20 or an > 100:
        return None
    off, qs, ans = 12, [], []
    try:
        for _ in range(qd):
            name, off = _dns_name(p, off)
            qt, qc = struct.unpack("!HH", p[off:off + 4])
            off += 4
            qs.append((name.lower(), qt))
        for _ in range(an):
            name, off = _dns_name(p, off)
            rt, rc, ttl, rl = struct.unpack("!HHIH", p[off:off + 10])
            off += 10
            rd = p[off:off + rl]
            if rt == 1 and rl == 4:
                val = ip4(rd)
            elif rt == 28 and rl == 16:
                val = ip6(rd)
            elif rt in (5, 2, 12):
                val = _dns_name(p, off)[0]
            elif rt == 16:
                val = rd[1:1 + rd[0]].decode("utf-8", "replace") if rd else ""
            else:
                val = "%d bytes" % rl
            ans.append({"name": name.lower(), "type": QTYPES.get(rt, str(rt)), "ttl": ttl, "data": val})
            off += rl
    except Exception:
        pass
    if not qs:
        return None
    return {"id": tid, "response": bool(flags & 0x8000), "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
            "qname": qs[0][0], "qtype": QTYPES.get(qs[0][1], str(qs[0][1])), "answers": ans}


# --------------------------------------------------------------------------- TLS / HTTP (stream level)
_GREASE = {((i << 4) | 0xA) << 8 | ((i << 4) | 0xA) for i in range(16)}


def _tlsv(v):
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(v, "0x%04x" % v)


def parse_tls(data):
    """Parse the first TLS handshake message of a reassembled stream direction."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 3:
        return None
    rec_len = struct.unpack("!H", data[3:5])[0]
    hs, rest = data[5:5 + rec_len], data[5 + rec_len:]
    if len(hs) < 4:
        return None
    need = 4 + int.from_bytes(hs[1:4], "big")
    while len(hs) < need and len(rest) > 5 and rest[0] == 0x16:
        l2 = struct.unpack("!H", rest[3:5])[0]
        hs += rest[5:5 + l2]
        rest = rest[5 + l2:]
    try:
        if hs[0] == 1:
            return _client_hello(hs)
        if hs[0] == 2:
            sid = hs[38]
            return {"type": "server_hello", "version": _tlsv(struct.unpack("!H", hs[4:6])[0]),
                    "cipher": "0x%04x" % struct.unpack("!H", hs[39 + sid:41 + sid])[0]}
    except Exception:
        return {"type": "partial"}
    return None


def _client_hello(hs):
    ver = struct.unpack("!H", hs[4:6])[0]
    i = 38
    i += 1 + hs[i]
    cl = struct.unpack("!H", hs[i:i + 2])[0]
    ciphers = [struct.unpack("!H", hs[i + 2 + k:i + 4 + k])[0] for k in range(0, cl, 2)]
    i += 2 + cl
    i += 1 + hs[i]
    sni, alpn, exts, curves, pf, sv = "", [], [], [], [], []
    if i + 2 <= len(hs):
        el = struct.unpack("!H", hs[i:i + 2])[0]
        i += 2
        end = min(len(hs), i + el)
        while i + 4 <= end:
            et, ln = struct.unpack("!HH", hs[i:i + 4])
            d = hs[i + 4:i + 4 + ln]
            exts.append(et)
            if et == 0 and len(d) > 5:
                sni = d[5:5 + struct.unpack("!H", d[3:5])[0]].decode("ascii", "replace")
            elif et == 16 and len(d) > 2:
                j = 2
                while j < len(d):
                    alpn.append(d[j + 1:j + 1 + d[j]].decode("ascii", "replace"))
                    j += 1 + d[j]
            elif et == 10 and len(d) > 2:
                curves = [struct.unpack("!H", d[2 + k:4 + k])[0] for k in range(0, len(d) - 2, 2)]
            elif et == 11 and d:
                pf = list(d[1:])
            elif et == 43 and d:
                sv = [struct.unpack("!H", d[1 + k:3 + k])[0] for k in range(0, d[0], 2)]
            i += 4 + ln
    f = lambda xs: "-".join(str(x) for x in xs if x not in _GREASE)
    ja3s = ",".join([str(ver), f(ciphers), f(exts), f(curves), f(pf)])
    return {"type": "client_hello", "version": _tlsv(0x0304 if 0x0304 in sv else ver), "sni": sni, "alpn": alpn, "ciphers": len(ciphers),
            "ja3": hashlib.md5(ja3s.encode()).hexdigest(), "ja3_string": ja3s}  # JA3 uses MD5 by specification (fingerprint, not security)


HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
_RESP_RE = re.compile(rb"HTTP/1\.[01] (\d{3}) ([^\r\n]*)\r\n(.*?)\r\n\r\n", re.S)


def _headers(lines):
    return {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in lines if ":" in l}


def parse_http_stream(client, server):
    """Extract request/response metadata from reassembled plaintext HTTP. Secret values are flagged, never stored."""
    if not client.startswith(HTTP_METHODS):
        return []
    reqs, resps = [], []
    for blk in client[:2_000_000].split(b"\r\n\r\n")[:300]:
        if blk.startswith(HTTP_METHODS):
            lines = blk.decode("latin-1", "replace").split("\r\n")
            parts = lines[0].split(" ")
            hd = _headers(lines[1:])
            reqs.append({"method": parts[0], "uri": parts[1][:300] if len(parts) > 1 else "", "host": hd.get("host", ""),
                         "user_agent": hd.get("user-agent", "")[:200], "auth_header": "authorization" in hd,
                         "auth_scheme": hd.get("authorization", "").split(" ")[0] if "authorization" in hd else "",
                         "cookie": "cookie" in hd, "content_type": hd.get("content-type", "")})
    for m in _RESP_RE.finditer(server[:2_000_000]):
        hd = _headers(m.group(3).decode("latin-1", "replace").split("\r\n"))
        resps.append({"status": int(m.group(1)), "reason": m.group(2).decode("latin-1", "replace"), "resp_type": hd.get("content-type", ""), "server_hdr": hd.get("server", "")})
    out = []
    for i, r in enumerate(reqs):
        r = dict(r)
        if i < len(resps):
            r.update(resps[i])
        out.append(r)
    return out


# --------------------------------------------------------------------------- packet dissection
def dissect(no, ts, link, data, orig_len):
    """Return a compact packet record (dict)."""
    pk = {"no": no, "ts": ts, "len": orig_len or len(data), "src": "", "dst": "", "proto": "OTHER", "sport": None, "dport": None,
          "flags": 0, "seq": 0, "ack": 0, "ttl": None, "pl": 0, "eth_src": "", "eth_dst": "", "info": "", "payload": b"", "ipv": 0}
    try:
        off, et = 0, 0
        if link == 1:
            if len(data) < 14:
                return pk
            pk["eth_dst"], pk["eth_src"] = mac(data[0:6]), mac(data[6:12])
            et, off = struct.unpack("!H", data[12:14])[0], 14
            while et in (0x8100, 0x88A8) and len(data) >= off + 4:
                et, off = struct.unpack("!H", data[off + 2:off + 4])[0], off + 4
        elif link == 113 and len(data) >= 16:
            et, off = struct.unpack("!H", data[14:16])[0], 16
            if data[4:6] == b"\x00\x06":
                pk["eth_src"] = mac(data[6:12])
        elif link == 276 and len(data) >= 20:
            et, off = struct.unpack("!H", data[0:2])[0], 20
        elif link == 0 and len(data) >= 4:
            et, off = (ETH_IPV4 if struct.unpack("<I", data[:4])[0] == 2 else ETH_IPV6), 4
        elif link in (101, 12, 228, 229) and data:
            et = ETH_IPV4 if data[0] >> 4 == 4 else ETH_IPV6
        else:
            pk["info"] = "unsupported link type %d" % link
            return pk
        if et == ETH_ARP:
            return _arp(pk, data, off)
        if et == ETH_IPV4 and len(data) >= off + 20:
            ihl = (data[off] & 15) * 4
            pk["ipv"], pk["ttl"], proto = 4, data[off + 8], data[off + 9]
            pk["src"], pk["dst"] = ip4(data[off + 12:off + 16]), ip4(data[off + 16:off + 20])
            frag = struct.unpack("!H", data[off + 6:off + 8])[0]
            tot = struct.unpack("!H", data[off + 2:off + 4])[0]
            body = data[off + ihl:off + tot] if tot >= ihl else data[off + ihl:]
            if frag & 0x1FFF:
                pk["proto"], pk["info"] = "IPv4-FRAG", "fragment offset %d" % ((frag & 0x1FFF) * 8)
                return pk
        elif et == ETH_IPV6 and len(data) >= off + 40:
            pk["ipv"], pk["ttl"], proto = 6, data[off + 7], data[off + 6]
            pk["src"], pk["dst"] = ip6(data[off + 8:off + 24]), ip6(data[off + 24:off + 40])
            body = data[off + 40:]
            while proto in (0, 43, 60, 44) and len(body) >= 8:
                nxt = body[0]
                o = 8 if proto == 44 else (body[1] + 1) * 8
                body, proto = body[o:], nxt
        else:
            pk["info"] = "ethertype %s" % hex(et)
            return pk
        _l4(pk, proto, body)
    except Exception as ex:
        pk["info"] = (pk["info"] + " malformed:" + type(ex).__name__).strip()
    return pk


def _arp(pk, d, o):
    if len(d) < o + 28:
        return pk
    op = struct.unpack("!H", d[o + 6:o + 8])[0]
    sha, spa, tha, tpa = mac(d[o + 8:o + 14]), ip4(d[o + 14:o + 18]), mac(d[o + 18:o + 24]), ip4(d[o + 24:o + 28])
    pk.update(proto="ARP", src=spa, dst=tpa, arp={"op": "request" if op == 1 else "reply" if op == 2 else str(op), "sha": sha, "spa": spa, "tha": tha, "tpa": tpa})
    pk["info"] = ("Who has %s? Tell %s" % (tpa, spa)) if op == 1 else ("%s is at %s" % (spa, sha))
    return pk


def _l4(pk, proto, body):
    if proto == 6 and len(body) >= 20:
        sp, dp, seq, ack, offf, fl = struct.unpack("!HHIIBB", body[:14])
        pay = body[(offf >> 4) * 4:]
        pk.update(proto="TCP", sport=sp, dport=dp, seq=seq, ack=ack, flags=fl & 0x3F, pl=len(pay), payload=bytes(pay[:65535]))
        names = [n for b, n in ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH"), (32, "URG")) if fl & b]
        pk["info"] = "%d → %d [%s] len=%d" % (sp, dp, ",".join(names), len(pay))
    elif proto == 17 and len(body) >= 8:
        sp, dp = struct.unpack("!HH", body[:4])
        pay = body[8:]
        pk.update(proto="UDP", sport=sp, dport=dp, pl=len(pay), payload=bytes(pay[:65535]))
        pk["info"] = "%d → %d len=%d" % (sp, dp, len(pay))
        if sp in (53, 5353) or dp in (53, 5353):
            d = parse_dns(pay)
            if d:
                pk["proto"], pk["dns"] = "DNS", d
                pk["info"] = ("Response %s %s %s" % (d["qname"], d["qtype"], d["rcode"])) if d["response"] else ("Query %s %s" % (d["qname"], d["qtype"]))
    elif proto in (1, 58) and len(body) >= 4:
        pk.update(proto="ICMP" if proto == 1 else "ICMPv6", pl=max(0, len(body) - 8), payload=bytes(body[8:][:2048]), icmp_type=body[0])
        pk["info"] = "type %d code %d" % (body[0], body[1])
    else:
        pk["proto"] = "IP-%d" % proto
