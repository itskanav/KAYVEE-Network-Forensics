"""Streaming PCAP / PCAPNG reader and PCAP writer (no third-party dependencies)."""
import struct, os

LINK_ETHERNET = 1


class PcapError(Exception):
    pass


def iter_packets(path, progress=None):
    """Yield (timestamp_float, linktype, data, orig_len). Truncated trailing data is tolerated."""
    size = max(1, os.path.getsize(path))
    with open(path, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            raise PcapError("File is too small to be a capture.")
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f, size, progress)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _iter_pcap(f, magic, size, progress)
        else:
            raise PcapError("Unrecognised file signature - not a PCAP or PCAPNG capture.")


def _iter_pcap(f, magic, size, progress):
    little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    e = "<" if little else ">"
    hdr = f.read(24)
    if len(hdr) < 24:
        raise PcapError("Truncated PCAP global header.")
    network = struct.unpack(e + "I", hdr[20:24])[0]
    div = 1e9 if nano else 1e6
    n = 0
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            break
        sec, frac, caplen, origlen = struct.unpack(e + "IIII", rec)
        if caplen > 0x4000000:
            break  # corrupt record header
        data = f.read(caplen)
        if len(data) < caplen:
            break
        yield sec + frac / div, network & 0xFFFF, data, origlen
        n += 1
        if progress and n % 2000 == 0:
            progress(f.tell() / size)


def _iter_pcapng(f, size, progress):
    e = "<"
    ifaces = []  # (linktype, ts_divisor)
    n = 0
    while True:
        h = f.read(8)
        if len(h) < 8:
            break
        if h[:4] == b"\x0a\x0d\x0d\x0a":  # section header: detect endianness
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            tlen = struct.unpack(e + "I", h[4:8])[0]
            f.read(max(0, tlen - 12))
            ifaces = []
            continue
        btype, tlen = struct.unpack(e + "II", h)
        if tlen < 12 or tlen > 0x8000000:
            break
        body = f.read(tlen - 8)
        if len(body) < tlen - 8:
            break
        body = body[:-4]
        if btype == 1 and len(body) >= 8:  # interface description
            link = struct.unpack(e + "H", body[:2])[0]
            div, opts, i = 1e6, body[8:], 0
            while i + 4 <= len(opts):
                code, ol = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ol >= 1:  # if_tsresol
                    v = opts[i + 4]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                i += 4 + ((ol + 3) & ~3)
            ifaces.append((link, div))
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            ifid, th, tl, cap, orig = struct.unpack(e + "IIIII", body[:20])
            link, div = ifaces[ifid] if ifid < len(ifaces) else (1, 1e6)
            yield ((th << 32) | tl) / div, link, body[20:20 + cap], orig
            n += 1
        elif btype == 3 and len(body) >= 4:  # simple packet (no timestamp)
            orig = struct.unpack(e + "I", body[:4])[0]
            yield 0.0, (ifaces[0][0] if ifaces else 1), body[4:4 + orig], orig
            n += 1
        if progress and n and n % 2000 == 0:
            progress(f.tell() / size)


class PcapWriter:
    """Minimal classic-PCAP writer used for live-capture evidence files."""

    def __init__(self, path, linktype=LINK_ETHERNET, snaplen=65535):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.count = 0

    def write(self, ts, data, orig_len=None):
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), orig_len or len(data)))
        self.f.write(data)
        self.count += 1

    def flush(self):
        self.f.flush()

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass
