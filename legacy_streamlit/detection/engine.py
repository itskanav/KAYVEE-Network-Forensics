import pandas as pd
import numpy as np

def run_detections(packets: pd.DataFrame) -> pd.DataFrame:
    alerts=[]
    def add(rule,severity,source,description,evidence):
        alerts.append({"rule":rule,"severity":severity,"source_ip":source,"description":description,"evidence":str(evidence)})
    if packets.empty: return pd.DataFrame(columns=["rule","severity","source_ip","description","evidence"])
    dns=packets[packets["dns_query"].fillna("")!=""]
    if not dns.empty:
        for src,g in dns.groupby("src_ip"):
            long_count=sum(len(x)>45 for x in g["dns_query"].astype(str))
            if len(g)>=40 or long_count>=3:
                add("DNS_VOLUME_OR_LONG_LABEL","High" if long_count>=3 else "Medium",src,
                    "DNS activity may be unusual; investigate for possible tunneling.",f"{len(g)} queries; {long_count} long names")
    tcp=packets[packets["protocol"].isin(["TCP","TLS/HTTPS","HTTP"])]
    for src,g in tcp.groupby("src_ip"):
        ports=g["dst_port"].dropna().astype(int).nunique()
        if ports>=20:
            add("PORT_SCAN_HEURISTIC","High",src,"One source contacted many destination ports.",f"{ports} unique destination ports")
        # repeated destination endpoint indicator, not proof of brute force
        endpoint_counts=g.groupby(["dst_ip","dst_port"],dropna=False).size()
        if not endpoint_counts.empty:
            target,count=endpoint_counts.idxmax(),int(endpoint_counts.max())
            if count>=50:
                add("REPEATED_CONNECTIONS","Medium",src,"Repeated connections to one endpoint may indicate retries or brute-force-like activity.",f"{count} packets to {target[0]}:{target[1]}")
    if len(packets)>=20:
        counts=packets.groupby("src_ip").size()
        mean=float(counts.mean()); std=float(counts.std(ddof=0))
        if std>0:
            for src,count in counts.items():
                z=(count-mean)/std
                if z>=3 and count>=30:
                    add("HOST_VOLUME_ANOMALY","Medium",src,"Source packet volume is a statistical outlier in this capture.",f"{count} packets; z-score {z:.2f}")
    for _,r in packets[packets["artifact_indicator"].fillna("")!=""].iterrows():
        add("ARTIFACT_INDICATOR","Medium",r["src_ip"],r["artifact_indicator"],f"packet {r['packet_no']} to {r['dst_ip']}")
    return pd.DataFrame(alerts,columns=["rule","severity","source_ip","description","evidence"]).drop_duplicates()
