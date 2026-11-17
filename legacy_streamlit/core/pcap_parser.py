import io
import math
import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

def _entropy(s):
    if not s: return 0.0
    from collections import Counter
    n=len(s)
    return -sum((c/n)*math.log2(c/n) for c in Counter(s).values())

def parse_pcap(raw: bytes, filename: str):
    rows=[]
    reader=PcapReader(io.BytesIO(raw))
    try:
        for idx,p in enumerate(reader):
            try:
                ts=float(p.time)
                length=int(len(p))
                src=dst=""; proto="OTHER"; sport=dport=None
                dns_query=dns_qtype=""; http_host=""; tls_sni=""; artifact=""
                if IP in p:
                    src,dst=p[IP].src,p[IP].dst
                elif IPv6 in p:
                    src,dst=p[IPv6].src,p[IPv6].dst
                if TCP in p:
                    proto="TCP"; sport=int(p[TCP].sport); dport=int(p[TCP].dport)
                elif UDP in p:
                    proto="UDP"; sport=int(p[UDP].sport); dport=int(p[UDP].dport)
                elif ICMP in p: proto="ICMP"
                if DNS in p and p[DNS].qd:
                    try:
                        q=p[DNS].qd
                        dns_query=bytes(q.qname).decode("utf-8","replace").rstrip(".")
                        dns_qtype=str(q.qtype)
                        label=max(dns_query.split(".") or [""],key=len)
                        if len(label)>=45 or _entropy(label)>=3.7:
                            artifact="DNS label unusually long/high entropy"
                    except Exception: pass
                payload=bytes(p[Raw].load) if Raw in p else b""
                text=payload[:8192].decode("latin-1","ignore")
                if text.startswith(("GET ","POST ","HEAD ","PUT ","DELETE ","OPTIONS ")):
                    proto="HTTP"
                    for line in text.splitlines()[:40]:
                        if line.lower().startswith("host:"):
                            http_host=line.split(":",1)[1].strip()
                        if line.lower().startswith(("authorization: basic","authorization: bearer")):
                            artifact=(artifact+"; " if artifact else "")+"Authorization header observed (value not retained)"
                        if line.lower().startswith("cookie:"):
                            artifact=(artifact+"; " if artifact else "")+"Cookie header observed (value not retained)"
                # TLS handshake metadata is often split across packets; this minimal parser intentionally avoids claiming full TLS decoding.
                if sport==443 or dport==443:
                    if proto=="TCP": proto="TLS/HTTPS"
                rows.append({"packet_no":idx+1,"timestamp":ts,"length":length,"src_ip":src,"dst_ip":dst,
                    "protocol":proto,"src_port":sport,"dst_port":dport,"dns_query":dns_query,
                    "dns_qtype":dns_qtype,"http_host":http_host,"tls_sni":tls_sni,
                    "artifact_indicator":artifact,"raw_payload":text[:1000] if proto=="HTTP" else ""})
            except Exception:
                continue
    finally:
        reader.close()
    df=pd.DataFrame(rows,columns=["packet_no","timestamp","length","src_ip","dst_ip","protocol","src_port","dst_port","dns_query","dns_qtype","http_host","tls_sni","artifact_indicator","raw_payload"])
    meta={"filename":filename,"parsed_packets":len(df),"parser":"Scapy PcapReader"}
    return df,meta
