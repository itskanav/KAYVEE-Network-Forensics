"""Capture analysis pipeline: parses a capture and builds hosts, flows, TCP streams, DNS, HTTP, TLS and ARP data.
Only facts present in the capture are recorded - nothing is simulated."""
import base64, math, time
from collections import Counter, defaultdict
from . import dissect as D
from .pcapio import iter_packets
from .netutil import ip_class, is_local, is_public, registered_domain

MAX_PACKETS = 500_000            # safety cap for in-memory analysis (~600 MB RAM at the cap)
STREAM_CAP = 1_048_576           # bytes kept per direction while reassembling
STREAM_VIEW = 32_768             # bytes persisted per direction for the stream viewer
MAX_FLOWS = 200_000


class P:
    __slots__ = ("no", "ts", "src", "dst", "proto", "sport", "dport", "flags", "ttl", "len", "pl", "eth_src", "eth_dst", "ipv", "icmp_type", "seq", "ack")

    def __init__(self, k):
        self.no, self.ts, self.src, self.dst, self.proto = k["no"], k["ts"], k["src"], k["dst"], k["proto"]
        self.sport, self.dport, self.flags, self.ttl, self.len, self.pl = k["sport"], k["dport"], k["flags"], k["ttl"], k["len"], k["pl"]
        self.eth_src, self.eth_dst, self.ipv, self.icmp_type = k["eth_src"], k["eth_dst"], k["ipv"], k.get("icmp_type")
        self.seq, self.ack = k["seq"], k["ack"]


def _flow_new(fid, proto, c, cp, s, sp, ts):
    return {"id": fid, "proto": proto, "client": c, "cport": cp, "server": s, "sport": sp, "start": ts, "end": ts, "c_pkts": 0, "s_pkts": 0,
            "c_bytes": 0, "s_bytes": 0, "c_pl": 0, "s_pl": 0, "syn": False, "synack": False, "fin": False, "rst": False, "acked": False,
            "pkt_nos": [], "_seg": ({}, {}), "_isn": [None, None], "_stored": [0, 0], "midstream": False, "syn_ts": ts}


class Analyzer:
    def __init__(self, geo=None, progress=None):
        self.geo, self.progress = geo, progress
        self.pkts, self.rows = [], []
        self.total = self.skipped = 0
        self.bytes = 0
        self.t0 = self.t1 = None
        self.protos, self.links = Counter(), Counter()
        self.hosts = {}
        self.flows, self.flow_list, self.flow_seq = {}, [], 0
        self.dns, self.arp = [], []
        self.resolved = defaultdict(set)    # name -> ips seen in DNS answers of this capture
        self.truncated = False

    # ------------------------------------------------------------------ feed
    def run(self, path):
        def prog(f):
            if self.progress:
                self.progress(f)
        n = 0
        for ts, link, data, orig in iter_packets(path, prog):
            n += 1
            if n > MAX_PACKETS:
                self.truncated = True
                break
            self.links[link] += 1
            self.feed(D.dissect(n, ts, link, data, orig))
        self.finalize()
        return self

    def host(self, ip, ts):
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = {"ip": ip, "pkts_out": 0, "pkts_in": 0, "bytes_out": 0, "bytes_in": 0, "first": ts, "last": ts, "macs": set(), "protos": Counter(),
                                  "ttls": Counter(), "server_ports": Counter(), "client_ports": Counter(), "peers": set(), "names": set(), "dns_queries": 0}
        if ts > h["last"]:
            h["last"] = ts
        if ts < h["first"]:
            h["first"] = ts
        return h

    def feed(self, pk):
        self.total += 1
        ts = pk["ts"] if pk["ts"] else (self.t1 or 0)
        pk["ts"] = ts
        self.bytes += pk["len"]
        self.t0 = ts if self.t0 is None else min(self.t0, ts)
        self.t1 = ts if self.t1 is None else max(self.t1, ts)
        self.protos[pk["proto"]] += 1
        p = P(pk)
        self.pkts.append(p)
        self.rows.append((p.no, ts, p.src, p.dst, p.proto, p.sport, p.dport, p.len, pk["info"][:240]))
        if not p.src:
            self.skipped += 1
            return
        hs, hd = self.host(p.src, ts), self.host(p.dst, ts)
        hs["pkts_out"] += 1; hs["bytes_out"] += p.len; hd["pkts_in"] += 1; hd["bytes_in"] += p.len
        hs["protos"][p.proto] += 1
        if p.eth_src:
            hs["macs"].add(p.eth_src)
        if p.ttl is not None:
            hs["ttls"][p.ttl] += 1
        if len(hs["peers"]) < 500:
            hs["peers"].add(p.dst)
        if len(hd["peers"]) < 500:
            hd["peers"].add(p.src)
        if p.proto == "ARP":
            a = pk["arp"]
            self.arp.append({"no": p.no, "ts": ts, "op": a["op"], "sha": a["sha"], "spa": a["spa"], "tha": a["tha"], "tpa": a["tpa"], "eth_src": p.eth_src, "eth_dst": p.eth_dst})
        elif "dns" in pk:
            d = pk["dns"]
            rec = {"no": p.no, "ts": ts, "src": p.src, "dst": p.dst, "qname": d["qname"], "qtype": d["qtype"], "response": d["response"], "rcode": d["rcode"],
                   "answers": d["answers"][:8], "size": p.pl, "id": d["id"]}
            if len(self.dns) < 300000:
                self.dns.append(rec)
            if not d["response"]:
                hs["dns_queries"] += 1
            for a in d["answers"]:
                if a["type"] in ("A", "AAAA"):
                    self.resolved[a["name"]].add(a["data"])
        if p.proto in ("TCP", "UDP", "DNS", "ICMP", "ICMPv6") and len(self.flow_list) < MAX_FLOWS:
            self._flow(p, pk)

    def _flow(self, p, pk):
        l4 = "UDP" if p.proto == "DNS" else p.proto
        if l4 in ("TCP", "UDP"):
            a, b = (p.src, p.sport), (p.dst, p.dport)
        else:
            a, b = (p.src, 0), (p.dst, 0)
        key = (l4,) + (a + b if a <= b else b + a)
        f = self.flows.get(key)
        syn_only = l4 == "TCP" and (p.flags & 0x12) == 0x02
        if f and l4 == "TCP" and syn_only and f["syn"] and (f["fin"] or f["rst"] or f["synack"]) and p.ts - f["end"] >= 0:
            f = None  # connection re-use of the same 4-tuple -> new flow
        if f is None:
            self.flow_seq += 1
            if l4 == "TCP" and (p.flags & 0x12) == 0x12:       # first seen packet is SYN-ACK: sender is the server
                f = _flow_new(self.flow_seq, l4, p.dst, p.dport, p.src, p.sport, p.ts)
            elif l4 == "TCP" and not syn_only:                 # mid-stream: the lower port is assumed to be the service
                srv_first = (p.sport or 0) < (p.dport or 0) and (p.sport or 0) < 49152
                f = _flow_new(self.flow_seq, l4, p.dst if srv_first else p.src, p.dport if srv_first else p.sport, p.src if srv_first else p.dst,
                              p.sport if srv_first else p.dport, p.ts)
                f["midstream"] = True
            else:
                f = _flow_new(self.flow_seq, l4, p.src, p.sport, p.dst, p.dport, p.ts)
            self.flows[key] = f
            self.flow_list.append(f)
        out = (p.src == f["client"] and (p.sport or 0) == (f["cport"] or 0))
        d = 0 if out else 1
        f["end"] = p.ts
        f["c_pkts" if out else "s_pkts"] += 1
        f["c_bytes" if out else "s_bytes"] += p.len
        f["c_pl" if out else "s_pl"] += p.pl
        if len(f["pkt_nos"]) < 400:
            f["pkt_nos"].append(p.no)
        if l4 == "TCP":
            fl = p.flags
            if fl & 2:
                if fl & 16:
                    f["synack"] = True
                else:
                    f["syn"] = True
                    f["syn_ts"] = p.ts
            if fl & 1: f["fin"] = True
            if fl & 4: f["rst"] = True
            if fl & 16 and not fl & 2 and (f["synack"] or f["midstream"]): f["acked"] = True
            if fl & 2 and f["_isn"][d] is None:
                f["_isn"][d] = (p.seq + 1) & 0xFFFFFFFF
            if p.pl and f["_stored"][d] < STREAM_CAP:
                seg = f["_seg"][d]
                if p.seq not in seg:
                    seg[p.seq] = pk["payload"][:p.pl]
                    f["_stored"][d] += p.pl
        elif p.pl and f["_stored"][d] < STREAM_CAP:       # UDP / ICMP payload preview (ordered by arrival)
            seg = f["_seg"][d]
            seg[len(seg)] = pk["payload"][:p.pl]
            f["_stored"][d] += p.pl

    # ------------------------------------------------------------------ finalize
    @staticmethod
    def _assemble(seg, isn, tcp=True):
        if not seg:
            return b"", 0
        if not tcp:
            return b"".join(seg[k] for k in sorted(seg)), 0
        base = isn if isn is not None else min(seg, key=lambda s: s)
        # sequence-wrap aware relative ordering
        items = sorted(((s - base) & 0xFFFFFFFF, v) for s, v in seg.items())
        out, gaps, exp = bytearray(), 0, 0
        for rel, v in items:
            if rel > 0x7FFFFFFF:      # data before ISN / wrapped garbage
                continue
            if rel > exp:
                gaps += 1
                exp = rel
            if rel + len(v) <= exp:
                continue
            out += v[exp - rel:]
            exp = rel + len(v) - 0
            if len(out) > STREAM_CAP:
                break
        return bytes(out), gaps

    def finalize(self):
        self.stream_data, self.http, self.tls, self.cleartext, self.auth_fail = {}, [], [], [], defaultdict(Counter)
        for f in self.flow_list:
            tcp = f["proto"] == "TCP"
            c, cg = self._assemble(f["_seg"][0], f["_isn"][0], tcp)
            s, sg = self._assemble(f["_seg"][1], f["_isn"][1], tcp)
            f["gaps"] = cg + sg
            f["service"] = D.SERVICES.get(f["sport"], D.SERVICES.get(f["cport"], "")) if f["proto"] != "ICMP" else "icmp"
            f["app"] = f["service"]
            if tcp:
                if f["rst"] and not f["synack"]:
                    f["state"] = "refused/reset"
                elif f["syn"] and not f["synack"]:
                    f["state"] = "no reply"
                elif f["fin"]:
                    f["state"] = "closed"
                elif f["rst"]:
                    f["state"] = "reset"
                elif f["midstream"]:
                    f["state"] = "midstream"
                else:
                    f["state"] = "established"
            else:
                f["state"] = "answered" if f["s_pkts"] else "unanswered"
            fid = f["id"]
            if c.startswith(D.HTTP_METHODS):
                f["app"] = "http"
                for t in D.parse_http_stream(c, s):
                    t.update(flow=fid, client=f["client"], server=f["server"], ts=f["start"])
                    self.http.append(t)
                    if t.get("status") in (401, 403):
                        self.auth_fail[(f["client"], f["server"], f["sport"])]["http"] += 1
                    if t["auth_header"]:
                        self.cleartext.append({"flow": fid, "client": f["client"], "server": f["server"], "port": f["sport"], "kind": "HTTP %s auth header" % (t["auth_scheme"] or "Authorization"), "ts": f["start"]})
            if tcp and (c[:1] == b"\x16" or s[:1] == b"\x16"):
                ch, sh = D.parse_tls(c), D.parse_tls(s)
                if ch or sh:
                    f["app"] = "tls"
                    t = {"flow": fid, "client": f["client"], "server": f["server"], "port": f["sport"], "ts": f["start"]}
                    if ch and ch.get("type") == "client_hello":
                        t.update(sni=ch["sni"], ja3=ch["ja3"], version=ch["version"], alpn=",".join(ch["alpn"]), ciphers=ch["ciphers"])
                    if sh and sh.get("type") == "server_hello":
                        t.update(server_version=sh["version"], cipher=sh["cipher"])
                    self.tls.append(t)
                    f["tls_sni"] = t.get("sni", "")
            if s.startswith(b"SSH-") or c.startswith(b"SSH-"):
                f["app"] = "ssh"
            if tcp and f["sport"] in (21, 2121) and (c[:5].upper() in (b"USER ", b"PASS ") or b"\r\nPASS " in c.upper()[:4000] or b"\r\nUSER " in c.upper()[:4000]):
                f["app"] = "ftp"
                self.cleartext.append({"flow": fid, "client": f["client"], "server": f["server"], "port": f["sport"], "kind": "FTP USER/PASS commands (values not retained)", "ts": f["start"]})
                self.auth_fail[(f["client"], f["server"], f["sport"])]["ftp"] += s.count(b"530 ")
            if tcp and f["sport"] == 23 and (c or s):
                self.cleartext.append({"flow": fid, "client": f["client"], "server": f["server"], "port": 23, "kind": "Telnet session (cleartext)", "ts": f["start"]})
            if tcp and f["sport"] in (25, 587) and c:
                self.auth_fail[(f["client"], f["server"], f["sport"])]["smtp"] += s.count(b"535 ")
            if c or s:
                self.stream_data[fid] = {"c": base64.b64encode(c[:STREAM_VIEW]).decode(), "s": base64.b64encode(s[:STREAM_VIEW]).decode(),
                                         "c_total": len(c), "s_total": len(s)}
            f.pop("_seg"); f.pop("_isn"); f.pop("_stored")
            f["duration"] = round(max(0.0, f["end"] - f["start"]), 6)
            self.host(f["server"], f["end"])["server_ports"][f["sport"]] += 1 if f["proto"] != "ICMP" else 0
            self.host(f["client"], f["end"])["client_ports"][f["cport"]] += 0
        for h in self.hosts.values():
            h["class"] = ip_class(h["ip"])
        self._bins()
        self._graph()

    def _bins(self):
        dur = max(0.0, (self.t1 or 0) - (self.t0 or 0))
        bin_s = next((b for b in (0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600, 86400) if dur / b <= 240), 86400)
        n = int(dur / bin_s) + 1
        self.bin_s = bin_s
        series = {k: [0] * n for k in ("out_b", "in_b", "int_b", "oth_b", "pkts")}
        for p in self.pkts:
            i = min(n - 1, int((p.ts - self.t0) / bin_s))
            series["pkts"][i] += 1
            if not p.src:
                series["oth_b"][i] += p.len
            elif is_local(p.src) and is_public(p.dst):
                series["out_b"][i] += p.len
            elif is_public(p.src) and is_local(p.dst):
                series["in_b"][i] += p.len
            elif is_local(p.src) and is_local(p.dst):
                series["int_b"][i] += p.len
            else:
                series["oth_b"][i] += p.len
        self.series = series

    def _graph(self):
        e = defaultdict(lambda: {"pkts": 0, "bytes": 0, "protos": Counter(), "first": None, "last": None})
        for p in self.pkts:
            if not p.src or not p.dst:
                continue
            x = e[(p.src, p.dst)]
            x["pkts"] += 1; x["bytes"] += p.len; x["protos"][p.proto] += 1
            x["first"] = p.ts if x["first"] is None else x["first"]
            x["last"] = p.ts
        self.edges = e
