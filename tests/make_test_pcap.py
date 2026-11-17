"""Builds a SYNTHETIC lab capture used only to validate the KAYVEE pipeline end-to-end.
The application itself never generates or injects data. Usage: python tests/make_test_pcap.py out.pcap [--ng]"""
import struct, socket, random, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kayvee.pcapio import PcapWriter

random.seed(7)
M = lambda s: bytes(int(x, 16) for x in s.split(":"))
MAC_GW, MAC_C, MAC_W, MAC_ATK = M("00:11:22:33:44:01"), M("00:11:22:33:44:10"), M("00:11:22:33:44:20"), M("66:66:66:66:66:66")
PKTS = []
T = [1_700_000_000.0]


def ip_hdr(src, dst, proto, payload, ttl=64):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.randrange(65535), 0, ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h + payload


def eth(dm, sm, et, payload):
    return dm + sm + struct.pack("!H", et) + payload


def tcp(sp, dp, seq, ack, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data


def udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def emit(ts, frame):
    PKTS.append((ts, frame))


def tcp_pkt(ts, s, d, sp, dp, seq, ack, fl, data=b"", sm=MAC_C, dm=MAC_W, ttl=64):
    emit(ts, eth(dm, sm, 0x0800, ip_hdr(s, d, 6, tcp(sp, dp, seq, ack, fl, data), ttl)))


def dns_q(name, qtype=1, tid=1):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_r(name, ip, tid=1, rcode=0):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    hdr = struct.pack("!HHHHHH", tid, 0x8180 | rcode, 1, 1 if ip else 0, 0, 0) + q + struct.pack("!HH", 1, 1)
    if ip:
        hdr += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr


def client_hello(sni):
    name = sni.encode()
    sn = struct.pack("!HHBH", len(name) + 3, 0, 0, len(name)) if False else struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext_sni = struct.pack("!HH", 0, len(sn)) + sn
    ext_ver = struct.pack("!HHB", 43, 3, 2) + b"\x03\x04"
    exts = ext_sni + ext_ver
    ciphers = struct.pack("!HHHH", 6, 0x1301, 0x1302, 0xC02F)
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + ciphers + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def conn(t, c, s, cp, sp, creq=b"", sresp=b"", cm=MAC_C, sm=MAC_W, close=True, chunk=1400):
    i, j = random.randrange(1 << 30), random.randrange(1 << 30)
    tcp_pkt(t, c, s, cp, sp, i, 0, 2, sm=cm, dm=sm)
    tcp_pkt(t + .001, s, c, sp, cp, j, i + 1, 0x12, sm=sm, dm=cm)
    tcp_pkt(t + .002, c, s, cp, sp, i + 1, j + 1, 0x10, sm=cm, dm=sm)
    i, j, t = i + 1, j + 1, t + .003
    for k in range(0, len(creq), chunk):
        part = creq[k:k + chunk]
        tcp_pkt(t, c, s, cp, sp, i, j, 0x18, part, sm=cm, dm=sm); i += len(part); t += .001
        tcp_pkt(t, s, c, sp, cp, j, i, 0x10, sm=sm, dm=cm); t += .001
    for k in range(0, len(sresp), chunk):
        part = sresp[k:k + chunk]
        tcp_pkt(t, s, c, sp, cp, j, i, 0x18, part, sm=sm, dm=cm); j += len(part); t += .001
        tcp_pkt(t, c, s, cp, sp, i, j, 0x10, sm=cm, dm=sm); t += .001
    if close:
        tcp_pkt(t, c, s, cp, sp, i, j, 0x11, sm=cm, dm=sm)
        tcp_pkt(t + .001, s, c, sp, cp, j, i + 1, 0x11, sm=sm, dm=cm)
    return t


def build():
    C, W, DNS, GW = "192.168.1.10", "192.168.1.20", "192.168.1.1", "192.168.1.1"
    t = T[0]
    # --- benign activity
    for k, (n, ip) in enumerate([("www.example.com", "93.184.216.34"), ("update.example.org", "151.101.1.20"), ("mail.example.net", "104.21.44.5")]):
        emit(t, eth(MAC_GW, MAC_C, 0x0800, ip_hdr(C, DNS, 17, udp(40000 + k, 53, dns_q(n, 1, 10 + k)))))
        emit(t + .02, eth(MAC_C, MAC_GW, 0x0800, ip_hdr(DNS, C, 17, udp(53, 40000 + k, dns_r(n, ip, 10 + k)))))
        t += 1
    conn(t, C, "93.184.216.34", 51000, 80, b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: lab-test\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: lab\r\n\r\n<html>hello forensics</html>", sm=MAC_GW)
    conn(t + 2, C, "151.101.1.20", 51001, 443, client_hello("update.example.org"), b"", sm=MAC_GW)
    conn(t + 3, C, "20.20.20.20", 51002, 21, b"USER lab\r\nPASS lab\r\n", b"220 FTP ready\r\n331 Password required\r\n230 Logged in\r\n")
    # --- port scan 192.168.1.66 -> W
    A = "192.168.1.66"
    ts = t + 10
    for pt in range(1, 61):
        tcp_pkt(ts, A, W, 44444, pt, 1000 + pt, 0, 2, sm=MAC_ATK, dm=MAC_W)
        tcp_pkt(ts + .0005, W, A, pt, 44444, 5000, 1001 + pt, 0x12 if pt in (22, 80) else 0x14, sm=MAC_W, dm=MAC_ATK)
        ts += .01
    # --- SSH brute force A -> W:22  (40 connections in ~30 s)
    ts = t + 20
    for k in range(40):
        conn(ts, A, W, 50000 + k, 22, b"SSH-2.0-libssh_0.9\r\n", b"SSH-2.0-OpenSSH_8.9\r\n", cm=MAC_ATK)
        ts += .75
    # --- HTTP auth failures
    ts = t + 55
    for k in range(8):
        conn(ts, A, W, 52000 + k, 80, b"GET /admin HTTP/1.1\r\nHost: 192.168.1.20\r\nAuthorization: Basic bGFiOmxhYg==\r\n\r\n", b"HTTP/1.1 401 Unauthorized\r\nServer: lab\r\n\r\n", cm=MAC_ATK)
        ts += 1
    # --- ARP spoofing: attacker claims gateway IP
    ts = t + 60
    emit(ts, eth(b"\xff" * 6, MAC_GW, 0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, MAC_GW, socket.inet_aton(GW), MAC_C, socket.inet_aton(C))))
    for k in range(14):
        ts += .5
        emit(ts, eth(MAC_C, MAC_ATK, 0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, MAC_ATK, socket.inet_aton(GW), MAC_C, socket.inet_aton(C))))
    # --- DNS tunnel
    ts = t + 70
    for k in range(45):
        lab = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(38))
        emit(ts, eth(MAC_GW, MAC_C, 0x0800, ip_hdr(C, DNS, 17, udp(41000 + k, 53, dns_q("%s.t.evil-tunnel.test" % lab, 16, 100 + k)))))
        ts += .2
    # --- DGA-like NXDOMAIN
    for k in range(20):
        nm = "".join(random.choice("bcdfghjklmnpqrstvwxz") for _ in range(14)) + ".test"
        emit(ts, eth(MAC_GW, MAC_C, 0x0800, ip_hdr(C, DNS, 17, udp(42000 + k, 53, dns_q(nm, 1, 300 + k)))))
        emit(ts + .01, eth(MAC_C, MAC_GW, 0x0800, ip_hdr(DNS, C, 17, udp(53, 42000 + k, dns_r(nm, None, 300 + k, 3)))))
        ts += .3
    # --- beaconing C -> 104.21.44.50:8443 every 30s, 12 times
    ts = t + 100
    for k in range(12):
        conn(ts + random.uniform(-.5, .5), C, "104.21.44.50", 53000 + k, 8443, b"ping%03d" % k, b"pong", sm=MAC_GW)
        ts += 30
    # --- 2 MB exfiltration C -> 185.199.108.7:443
    conn(t + 120, C, "185.199.108.7", 54000, 443, client_hello("files.upload-lab.test") + os.urandom(2_200_000), b"\x17\x03\x03\x00\x05hello", sm=MAC_GW, chunk=1400)
    # --- SYN flood from many sources to W:80
    ts = t + 150
    for k in range(400):
        s = "45.%d.%d.%d" % (random.randrange(60, 120), random.randrange(1, 250), random.randrange(1, 250))
        tcp_pkt(ts, s, W, random.randrange(1025, 65000), 80, random.randrange(1 << 30), 0, 2, sm=MAC_GW, dm=MAC_W)
        ts += .002
    # --- large ICMP payloads
    for k in range(8):
        emit(t + 160 + k, eth(MAC_GW, MAC_C, 0x0800, ip_hdr(C, "104.21.44.99", 1, struct.pack("!BBHHH", 8, 0, 0, 1, k) + os.urandom(400))))
    PKTS.sort(key=lambda x: x[0])


def write_pcap(path):
    w = PcapWriter(path)
    for ts, f in PKTS:
        w.write(ts, f)
    w.close()


def write_pcapng(path):
    def blk(t, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", t, total) + body + b"\0" * pad + struct.pack("<I", total)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHBxxx", 9, 1, 6) + struct.pack("<HH", 0, 0))
    for ts, f in PKTS:
        v = int(ts * 1e6)
        out += blk(6, struct.pack("<IIIII", 0, v >> 32, v & 0xFFFFFFFF, len(f), len(f)) + f)
    open(path, "wb").write(out)


if __name__ == "__main__":
    build()
    (write_pcapng if "--ng" in sys.argv else write_pcap)(sys.argv[1] if len(sys.argv) > 1 else "lab_capture.pcap")
    print("wrote", len(PKTS), "packets")
