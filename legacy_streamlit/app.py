import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from core.pcap_parser import parse_pcap
from detection.engine import run_detections
from forensics.evidence import sha256_bytes
from forensics.report import make_json_report, make_csv_report

st.set_page_config(page_title="KAYVEE | Network Forensics", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container{padding-top:1.4rem;max-width:1500px}
.hero{padding:1.4rem 1.6rem;border:1px solid #26394d;border-radius:18px;background:linear-gradient(120deg,#101c2c,#152a3d);margin-bottom:1rem}
.hero h1{margin:0;color:#e8f3ff;font-size:2rem}.hero p{margin:.4rem 0 0;color:#a9bfd3}
.small{color:#9fb3c8;font-size:.9rem}
div[data-testid="stMetric"]{background:#101c2c;border:1px solid #24394e;padding:12px;border-radius:12px}
</style>
<div class="hero"><h1>🛡️ KAYVEE Network Forensics</h1><p>PCAP investigation • Traffic reconstruction • Rule-based threat detection • Evidence integrity</p></div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Investigation")
    case_id = st.text_input("Case ID", "CASE-001")
    analyst = st.text_input("Analyst", "Network Forensics Analyst")
    st.caption("Upload a PCAP/PCAPNG file you are authorized to examine.")
    uploaded = st.file_uploader("Evidence capture", type=["pcap", "pcapng", "cap"])
    st.divider()
    st.markdown("**Models**")
    page = st.radio("Navigate", ["Overview", "Model 1 · Core Analysis", "Model 2 · Detection", "Evidence & Export"])
    st.divider()
    st.caption("Educational prototype. Findings are indicators, not proof of compromise.")

if not uploaded:
    st.info("Upload a PCAP or PCAPNG file in the sidebar to begin. For a quick smoke test, use a capture from your own lab or Wireshark.")
    c1,c2,c3=st.columns(3)
    c1.markdown("### Model 1\nProtocol parsing, DNS metadata, endpoints, conversations and artifact indicators.")
    c2.markdown("### Model 2\nHeuristic DNS tunnel, port-scan, repeated-connection, TLS metadata and anomaly rules.")
    c3.markdown("### Forensic handling\nSHA-256 input hash, case metadata and JSON/CSV exports.")
    st.stop()

raw = uploaded.getvalue()
evidence_hash = sha256_bytes(raw)
with st.spinner("Parsing capture… large files may take a little while."):
    try:
        packets, parse_meta = parse_pcap(raw, uploaded.name)
    except Exception as e:
        st.error(f"Could not parse this capture: {e}")
        st.stop()

if packets.empty:
    st.warning("No supported IP packets were found in this capture.")
    st.stop()

alerts = run_detections(packets)
total_packets = int(len(packets))
total_bytes = int(packets["length"].sum())
unique_hosts = int(pd.concat([packets["src_ip"],packets["dst_ip"]]).nunique())
sev_count = int(len(alerts))
conversations = packets.groupby(["src_ip","dst_ip","protocol"], dropna=False).agg(
    packets=("length","size"), bytes=("length","sum"), first_seen=("timestamp","min"), last_seen=("timestamp","max")
).reset_index()
conversations["duration_s"] = (conversations["last_seen"]-conversations["first_seen"]).clip(lower=0).round(3)
protocol_counts = packets["protocol"].value_counts().rename_axis("protocol").reset_index(name="packets")

if page == "Overview":
    st.subheader("Investigation overview")
    a,b,c,d=st.columns(4)
    a.metric("Packets", f"{total_packets:,}")
    b.metric("Bytes", f"{total_bytes:,}")
    c.metric("Unique IPs", unique_hosts)
    d.metric("Detection alerts", sev_count)
    st.caption(f"File: {uploaded.name} · Size: {len(raw):,} bytes · Case: {case_id}")
    st.markdown("#### Protocol distribution")
    st.plotly_chart(px.pie(protocol_counts, names="protocol", values="packets", hole=.55), use_container_width=True)
    l,r=st.columns(2)
    with l:
        st.markdown("#### Traffic over time")
        timeline=packets.copy()
        timeline["time"]=pd.to_datetime(timeline["timestamp"], unit="s", errors="coerce")
        bytime=timeline.dropna(subset=["time"]).set_index("time").resample("1min").size().reset_index(name="packets")
        st.plotly_chart(px.line(bytime,x="time",y="packets"),use_container_width=True)
    with r:
        st.markdown("#### Top destination IPs")
        top=packets["dst_ip"].value_counts().head(10).rename_axis("destination").reset_index(name="packets")
        st.plotly_chart(px.bar(top,x="packets",y="destination",orientation="h"),use_container_width=True)
    st.markdown("#### Highest priority findings")
    if alerts.empty: st.success("No configured heuristic rules fired on this capture.")
    else: st.dataframe(alerts.head(20), use_container_width=True, hide_index=True)

elif page == "Model 1 · Core Analysis":
    st.subheader("Model 1 — Core PCAP Analysis")
    tabs=st.tabs(["Packets & protocols","DNS metadata","Conversations","Artifact indicators"])
    with tabs[0]:
        st.write("Supported network-layer parsing with available transport/application metadata.")
        st.dataframe(packets.drop(columns=["raw_payload"],errors="ignore"),use_container_width=True,hide_index=True)
        st.download_button("Download packet table CSV",packets.drop(columns=["raw_payload"],errors="ignore").to_csv(index=False),"packets.csv","text/csv")
    with tabs[1]:
        dns=packets[packets["dns_query"].fillna("")!=""]
        st.metric("DNS queries observed",len(dns))
        st.dataframe(dns[["timestamp","src_ip","dst_ip","dns_query","dns_qtype","length"]],use_container_width=True,hide_index=True)
        if len(dns): st.plotly_chart(px.bar(dns["dns_query"].value_counts().head(15).rename_axis("query").reset_index(name="count"),x="count",y="query",orientation="h"),use_container_width=True)
        else: st.info("No DNS query names were decoded. DNS-over-HTTPS and encrypted payloads may not expose query names.")
    with tabs[2]:
        st.caption("Conversations are grouped by directional source/destination IP and protocol. They are not full bidirectional TCP stream reassembly.")
        st.dataframe(conversations.sort_values("bytes",ascending=False),use_container_width=True,hide_index=True)
    with tabs[3]:
        indicators=packets[packets["artifact_indicator"].fillna("")!=""]
        st.caption("Only safe indicators are reported. Encrypted HTTPS payloads are not decrypted and passwords are not extracted.")
        if indicators.empty: st.info("No configured artifact indicators found.")
        else: st.dataframe(indicators[["timestamp","src_ip","dst_ip","protocol","artifact_indicator","http_host","tls_sni"]],use_container_width=True,hide_index=True)

elif page == "Model 2 · Detection":
    st.subheader("Model 2 — Detection Engine")
    st.caption("Heuristic alerts need analyst validation; false positives are possible.")
    if alerts.empty:
        st.success("No configured detection rules fired.")
    else:
        filt=st.multiselect("Severity",sorted(alerts["severity"].unique()),default=sorted(alerts["severity"].unique()))
        st.dataframe(alerts[alerts["severity"].isin(filt)],use_container_width=True,hide_index=True)
        st.download_button("Export alerts CSV",alerts.to_csv(index=False),"alerts.csv","text/csv")
    st.markdown("#### Rule coverage")
    st.markdown("- DNS tunneling heuristic: unusually long/high-entropy-looking DNS labels and high query volume per source.\n- Port scan heuristic: many distinct destination ports from one source.\n- Repeated connection heuristic: repeated attempts to one endpoint.\n- Suspicious TLS metadata: certificate/SNI indicators only when available in the capture.\n- Statistical anomaly: unusually high per-host packet volume compared with the capture distribution.\n- Threat-intel matching: optional local indicator list; no live reputation lookup is performed.")

elif page == "Evidence & Export":
    st.subheader("Evidence integrity & report export")
    st.write("**Case ID:**",case_id)
    st.write("**Analyst:**",analyst)
    st.write("**Evidence filename:**",uploaded.name)
    st.write("**Evidence size:**",f"{len(raw):,} bytes")
    st.code(evidence_hash,language="text")
    st.caption("SHA-256 is calculated over the exact uploaded file bytes. Preserve the original capture and document acquisition/handling separately.")
    report=make_json_report(case_id, analyst, uploaded.name, len(raw), evidence_hash, parse_meta, packets, alerts)
    st.download_button("Download investigation report (JSON)",report,"kayvee_report.json","application/json")
    st.download_button("Download packets (CSV)",packets.drop(columns=["raw_payload"],errors="ignore").to_csv(index=False),"packets.csv","text/csv")
    st.download_button("Download conversations (CSV)",conversations.to_csv(index=False),"conversations.csv","text/csv")
    st.download_button("Download detections (CSV)",alerts.to_csv(index=False),"alerts.csv","text/csv")
    st.warning("This prototype exports JSON/CSV. PDF export can be added separately; do not present automated heuristics as conclusive evidence.")

st.divider()
st.markdown('<p class="small">KAYVEE • Offline-first analysis • No packets are uploaded to an external service by this app.</p>',unsafe_allow_html=True)
