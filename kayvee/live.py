"""Live packet capture. Linux: AF_PACKET raw socket (needs root/CAP_NET_RAW). Elsewhere: Scapy sniffer if installed.
Packets are written to a PCAP evidence file; the dashboard shows only counters computed from packets actually received."""
import os, sys, time, socket, threading, struct
from collections import Counter, deque
from . import dissect as D
from .pcapio import PcapWriter
from .netutil import is_local, is_public


def capability():
    if sys.platform.startswith("linux"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()
            return {"available": True, "backend": "AF_PACKET", "reason": "", "interfaces": _ifaces_linux()}
        except PermissionError:
            r = "Raw capture needs root privileges. Restart with: sudo python3 app.py (or grant CAP_NET_RAW to python)."
        except Exception as e:
            r = "Raw socket unavailable: %s" % e
    else:
        r = "Native raw capture is Linux-only."
    try:
        import scapy.all as sc  # noqa
        return {"available": True, "backend": "scapy", "reason": "", "interfaces": [{"name": n} for n in sc.get_if_list()]}
    except Exception:
        return {"available": False, "backend": None, "reason": r + " Alternative: record with Wireshark/dumpcap/tcpdump, then upload the file in PCAP Analyzer.", "interfaces": []}


def _ifaces_linux():
    out = []
    for _, n in socket.if_nameindex():
        st = ""
        try:
            st = open("/sys/class/net/%s/operstate" % n).read().strip()
        except Exception:
            pass
        out.append({"name": n, "state": st})
    return out


class LiveCapture:
    def __init__(self, evidence_dir):
        self.dir, self.lock = evidence_dir, threading.Lock()
        self.reset()

    def reset(self):
        self.running = False
        self.stop_evt = threading.Event()
        self.thread = None
        self.iface = self.path = self.error = None
        self.started = self.ended = None
        self.packets = self.bytes = self.dropped = 0
        self.protos, self.talkers, self.names = Counter(), Counter(), Counter()
        self.recent, self.series = deque(maxlen=80), deque(maxlen=300)
        self.writer = None
        self.cur = None

    def start(self, iface, max_seconds=0, max_packets=0):
        with self.lock:
            if self.running:
                raise RuntimeError("A capture is already running")
            cap = capability()
            if not cap["available"]:
                raise RuntimeError(cap["reason"])
            if iface not in [i["name"] for i in cap["interfaces"]]:
                raise ValueError("Unknown interface %r" % iface)
            self.reset()
            os.makedirs(self.dir, exist_ok=True)
            self.iface, self.started, self.running = iface, time.time(), True
            self.max_seconds, self.max_packets, self.backend = int(max_seconds or 0), int(max_packets or 0), cap["backend"]
            self.path = os.path.join(self.dir, "live_%s_%s.pcap" % (time.strftime("%Y%m%d_%H%M%S"), iface))
            link = 1
            try:
                if int(open("/sys/class/net/%s/type" % iface).read()) in (65534, 768, 769):
                    link = 101
            except Exception:
                pass
            self.writer = PcapWriter(self.path, link)
            self.link = link
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def _account(self, ts, data):
        pk = D.dissect(self.packets, ts, self.link, data, len(data))
        self.bytes += len(data)
        self.protos[pk["proto"]] += 1
        sec = int(ts)
        if not self.cur or self.cur["t"] != sec:
            if self.cur:
                self.series.append(self.cur)
            self.cur = {"t": sec, "out": 0, "in": 0, "int": 0, "oth": 0, "pkts": 0}
        c = self.cur
        c["pkts"] += 1
        s, d = pk["src"], pk["dst"]
        k = "out" if is_local(s) and is_public(d) else "in" if is_public(s) and is_local(d) else "int" if s and is_local(s) and is_local(d) else "oth"
        c[k] += len(data)
        if s:
            self.talkers[s] += len(data)
            self.talkers[d] += len(data)
        if "dns" in pk and not pk["dns"]["response"]:
            self.names[pk["dns"]["qname"]] += 1
        self.recent.append({"no": self.packets, "ts": ts, "src": s, "dst": d, "proto": pk["proto"], "len": pk["len"], "info": pk["info"][:120]})
        if len(self.talkers) > 5000:
            self.talkers = Counter(dict(self.talkers.most_common(1000)))

    def _on_packet(self, ts, data):
        self.packets += 1
        self.writer.write(ts, data)
        self._account(ts, data)
        if self.max_packets and self.packets >= self.max_packets or (self.max_seconds and time.time() - self.started >= self.max_seconds):
            self.stop_evt.set()

    def _run(self):
        try:
            if self.backend == "AF_PACKET":
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                s.bind((self.iface, 0)); s.settimeout(0.5)
                last = time.time()
                while not self.stop_evt.is_set():
                    try:
                        data, _ = s.recvfrom(65535)
                        self._on_packet(time.time(), data)
                    except socket.timeout:
                        pass
                    if self.max_seconds and time.time() - self.started >= self.max_seconds:
                        break
                    if time.time() - last > 1:
                        self.writer.flush(); last = time.time()
                s.close()
            else:
                from scapy.all import AsyncSniffer, raw
                sn = AsyncSniffer(iface=self.iface, store=False, prn=lambda p: self._on_packet(float(p.time), raw(p)))
                sn.start()
                while not self.stop_evt.is_set() and sn.running is not False:
                    time.sleep(0.3)
                    if self.max_seconds and time.time() - self.started >= self.max_seconds:
                        break
                sn.stop()
        except Exception as e:
            self.error = "%s: %s" % (type(e).__name__, e)
        finally:
            self.running = False
            self.ended = time.time()
            try:
                self.writer.flush()
            except Exception:
                pass

    def stop(self):
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=5)
        if self.cur:
            self.series.append(self.cur); self.cur = None
        if self.writer:
            self.writer.close()
        self.running = False
        self.ended = self.ended or time.time()

    def snapshot(self):
        dur = (self.ended or time.time()) - self.started if self.started else 0
        return {"running": self.running, "iface": self.iface, "path": self.path, "error": self.error, "started": self.started, "ended": self.ended, "duration": round(dur, 1),
                "packets": self.packets, "bytes": self.bytes, "pps": round(self.packets / dur, 1) if dur > 0 else 0, "bps": round(self.bytes * 8 / dur) if dur > 0 else 0,
                "protocols": dict(self.protos.most_common(10)), "talkers": self.talkers.most_common(10), "dns": self.names.most_common(10), "recent": list(self.recent)[-40:],
                "series": list(self.series)[-120:] + ([self.cur] if self.cur else []), "limits": {"max_seconds": getattr(self, "max_seconds", 0), "max_packets": getattr(self, "max_packets", 0)},
                "backend": getattr(self, "backend", None)}
