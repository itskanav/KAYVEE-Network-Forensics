"use strict";
const ST = {status: null, analyses: [], aid: null, ov: null, view: "", timers: [], globe: null, radar: null, live: null, busy: null};
const VIEWS = {};
const A = path => `/api/analyses/${ST.aid}/${path}`;
const hasA = () => !!(ST.aid && ST.ov);
const clearTimers = () => { ST.timers.forEach(t => clearInterval(t)); ST.timers = []; if (ST.globe) { ST.globe.destroy(); ST.globe = null; } if (ST.radar) ST.radar.dead = true; ST.radar = null; ST.cleanup && ST.cleanup(); ST.cleanup = null; };
const noAnalysis = (what = "this view") => `<div class="card">${empty("Waiting for evidence", `<p>No investigation is loaded, so ${esc(what)} has nothing real to display yet. Upload a PCAP/PCAPNG or capture live traffic to begin.</p>`, "pkt", `<a class="btn primary" href="#/pcap">${ic("up")} Upload a capture</a>`)}</div>`;
const pageHead = (t, p, extra = "") => `<div class="h-page"><div><h1>${esc(t)}</h1><p>${p}</p></div><div class="sp">${extra}</div></div>`;
const pktRows = rows => rows.map(r => ({...r, _attr: `data-pkt="${r.no}"`}));
const pktTable = rows => table([{label: "No.", key: "no", cls: "num"}, {label: "Time (UTC)", render: r => esc(fmtT(r.ts, 1).slice(11, 23))}, {label: "Source", render: r => ipb(r.src)}, {label: "Destination", render: r => ipb(r.dst)}, {label: "Protocol", render: r => `<span class="tag">${esc(r.proto)}</span>`}, {label: "Len", key: "len", cls: "num"}, {label: "Info", key: "info", cls: "wrap"}], pktRows(rows), {emptyTitle: "No packets", emptyBody: "No packets match."});
function addNoteBox(ref, onAdded) { return `<div class="field" style="margin-top:8px"><textarea class="input" rows="2" placeholder="Add an analyst note for ${esc(ref)}" data-noteref="${esc(ref)}"></textarea></div><button class="btn sm" data-addnote="${esc(ref)}">${ic("plus")} Save note</button>`; }
const noteList = ns => ns.length ? ns.map(n => `<div class="note-item"><small>${esc(n.author)} · ${esc(fmtT(n.ts))}</small><div>${esc(n.text)}</div></div>`).join("") : `<p style="color:var(--muted)">No notes yet.</p>`;

// ---------------------------------------------------------------- detail drawers
async function openIP(ip) {
  const tok = openDrawer(ip, "Loading host intelligence…");
  try {
    const h = await api(A("host/" + encodeURIComponent(ip))); const g = h.geo;
    const peers = table([{label: "Peer", render: r => ipb(r.s === ip ? r.d : r.s)}, {label: "Direction", render: r => r.s === ip ? "→ sent" : "← received"}, {label: "Packets", key: "pkts", cls: "num"}, {label: "Bytes", render: r => fmtB(r.bytes), cls: "num"}, {label: "Protocols", render: r => Object.keys(r.protos).map(p => `<span class="tag">${esc(p)}</span>`).join("")}, {label: "", render: r => `<button class="btn sm" data-pair="${esc(r.s)}|${esc(r.d)}">History</button>`}], h.peers_detail, {emptyTitle: "No peers", emptyBody: ""});
    const flows = table([{label: "Peer", render: r => ipb(r.client === ip ? r.server : r.client)}, {label: "Proto", key: "proto"}, {label: "Service", render: r => esc(r.app || r.service || r.sport)}, {label: "State", key: "state"}, {label: "Bytes", render: r => fmtB(r.c_bytes + r.s_bytes), cls: "num"}], h.flows.slice(0, 60).map(f => ({...f, _attr: `data-flow="${f.id}"`})), {emptyTitle: "No flows", emptyBody: ""});
    const html = `<div class="row" style="gap:18px;align-items:center"><div class="score-ring" style="--p:${h.score};--c:${SEV_COLOR[h.level]}"><span>${h.score}</span></div><div><div>${sev(h.level)} <span class="tag">${esc(h.class)}</span> <span class="tag">${esc(h.role)}</span></div><p style="margin:6px 0 0;color:var(--muted)">${h.alerts.length ? `Involved in ${h.alerts.length} finding(s).` : "No detection rule involves this host."}</p></div></div>
    <h4>Identity & location</h4><dl class="kv"><dt>Address class</dt><dd>${esc(h.class)}${h.ip_notes ? ` — ${esc(h.ip_notes)}` : ""}</dd><dt>Location</dt><dd>${g ? esc([g.city, g.country].filter(Boolean).join(", ")) + ` (${g.lat.toFixed(2)}, ${g.lon.toFixed(2)})` : "Unavailable"}</dd><dt>ASN / org</dt><dd>${g && g.asn ? esc("AS" + g.asn + " " + g.org) : "Unavailable"}</dd><dt>Names (from DNS in this capture)</dt><dd>${h.names.map(esc).join(", ") || "None observed"}</dd><dt>MAC address(es)</dt><dd class="mono">${h.macs.map(esc).join(", ") || "Not visible (routed traffic)"}</dd><dt>TTL values</dt><dd>${Object.entries(h.ttls).map(([t, n]) => `${t}×${n}`).join(", ") || "—"}</dd><dt>Services offered</dt><dd>${h.services.map(s => `<span class="tag">${s.port}</span>`).join("") || "None observed"}</dd><dt>First / last seen</dt><dd>${fmtT(h.first)} → ${fmtT(h.last)}</dd><dt>Traffic</dt><dd>sent ${fmtN(h.pkts_out)} pkts / ${fmtB(h.bytes_out)} · received ${fmtN(h.pkts_in)} pkts / ${fmtB(h.bytes_in)}</dd></dl>
    ${h.alert_details.length ? `<h4>Findings</h4>${h.alert_details.map(alertCard).join("")}` : ""}
    ${acc(`Communication history (${h.peers_detail.length} peers)`, peers, true)}${acc(`Flows (${h.flows.length})`, flows)}
    ${acc(`DNS queries (${h.dns.length})`, h.dns.length ? table([{label: "Time", render: r => esc(fmtT(r.ts).slice(11, 19))}, {label: "Name", key: "qname", cls: "wrap"}, {label: "Type", key: "qtype"}], h.dns.map(d => ({...d, _attr: `data-pkt="${d.no}"`}))) : empty("No DNS queries from this host", ""))}
    ${acc(`TLS handshakes (${h.tls.length})`, h.tls.length ? table([{label: "SNI", render: r => esc(r.sni || "—")}, {label: "Server", render: r => ipb(r.server)}, {label: "Version", render: r => esc(r.version || r.server_version || "—")}, {label: "JA3", render: r => `<span class="mono">${esc((r.ja3 || "").slice(0, 12))}</span>`}], h.tls) : empty("No TLS handshakes decoded", ""))}
    ${acc(`HTTP requests (${h.http.length})`, h.http.length ? table([{label: "Method", key: "method"}, {label: "Host", key: "host"}, {label: "URI", key: "uri", cls: "wrap"}, {label: "Status", render: r => esc(r.status || "—")}], h.http) : empty("No cleartext HTTP", ""))}
    ${acc("Analyst notes", `<div id="notes-${esc(ip)}">${noteList(h.notes)}</div>${addNoteBox(ip)}`)}`;
    drawerSet(tok, html, ip, `${h.class} host · ${fmtB(h.bytes_in + h.bytes_out)} observed`);
  } catch (e) { drawerSet(tok, errBox(e)); }
}
function alertCard(a) { return `<button class="alert" data-alert="${esc(a.id)}"><span class="bar" style="background:${SEV_COLOR[a.severity]}"></span><span><b>${esc(a.title)}</b><small>${esc(a.id)} · ${esc(a.description)}</small></span><span>${sev(a.severity)}</span></button>`; }
async function openAlert(id) {
  const tok = openDrawer(id, "Loading evidence…");
  try {
    const a = await api(A("alerts/" + id));
    const sts = ["new", "investigating", "confirmed", "false-positive"];
    const html = `<div class="row">${sev(a.severity)} <span class="tag">score ${a.score}</span> <span class="tag">confidence ${Math.round(a.confidence * 100)}%</span> ${a.mitre_id ? `<span class="tag">MITRE ${esc(a.mitre_id)} · ${esc(a.mitre_name)}</span>` : ""}</div>
    <p style="font-size:15px">${esc(a.description)}</p>
    <h4>Why it was detected</h4><div class="note info">${esc(a.reason)}</div>
    <h4>Parties</h4><dl class="kv"><dt>Actor</dt><dd>${ipb(a.src)}</dd><dt>Target</dt><dd>${ipb(a.dst)}</dd><dt>Window</dt><dd>${fmtT(a.ts_start)} → ${fmtT(a.ts_end)}</dd></dl>
    <h4>Evidence</h4><ul>${a.evidence.map(e => `<li>${esc(e)}</li>`).join("")}</ul>
    <h4>Suggested response</h4><p>${esc(a.recommendation || "Validate the finding manually against other logs.")}</p>
    <h4>Triage status</h4><div class="row" id="triage">${sts.map(s => `<button class="btn sm ${a.status === s ? "primary" : ""}" data-triage="${s}" data-aid="${esc(a.id)}">${s.replace("-", " ")}</button>`).join("")}</div>
    <h4>Related packets (${a.packet_nos.length})</h4>${pktTable(a.packets)}
    <h4>Analyst notes</h4><div id="notes-${esc(a.id)}">${noteList(a.notes)}</div>${addNoteBox(a.id)}`;
    drawerSet(tok, html, a.title, `${a.id} · ${a.category.replace(/_/g, " ").toLowerCase()}`);
  } catch (e) { drawerSet(tok, errBox(e)); }
}
async function openEvent(e) {
  if (!e) return; if (e.alert) return openAlert(e.alert);
  const tok = openDrawer(e.title, fmtT(e.ts));
  try { const p = await api(A(`packets/${e.packet_nos[0] || 1}`)); drawerSet(tok, `<p>${esc(e.title)} marks the ${e.title.includes("ends") ? "last" : "first"} packet of the capture.</p><h4>Related packet</h4>${packetBody(p)}`); } catch (x) { drawerSet(tok, errBox(x)); }
}
function packetBody(d) {
  const p = d.packet; const l4 = p.sport != null ? `${p.sport} → ${p.dport}` : "—";
  return `<dl class="kv"><dt>Packet</dt><dd>#${p.no} · ${fmtT(p.ts, 1)}</dd><dt>Protocol</dt><dd>${esc(p.proto)} ${p.ipv ? "(IPv" + p.ipv + ")" : ""}</dd><dt>Source</dt><dd>${ipb(p.src)} <span class="mono">${esc(p.eth_src)}</span></dd><dt>Destination</dt><dd>${ipb(p.dst)} <span class="mono">${esc(p.eth_dst)}</span></dd><dt>Ports</dt><dd>${l4}</dd><dt>TTL / length</dt><dd>${p.ttl ?? "—"} / ${p.len} bytes (captured ${d.frame_len})</dd><dt>TCP flags / seq</dt><dd>${p.proto === "TCP" ? `0x${p.flags.toString(16)} · seq ${p.seq} · ack ${p.ack}` : "—"}</dd><dt>Summary</dt><dd>${esc(p.info)}</dd></dl>
  ${p.arp ? `<h4>ARP</h4><dl class="kv"><dt>Operation</dt><dd>${esc(p.arp.op)}</dd><dt>Sender</dt><dd class="mono">${esc(p.arp.sha)} / ${esc(p.arp.spa)}</dd><dt>Target</dt><dd class="mono">${esc(p.arp.tha)} / ${esc(p.arp.tpa)}</dd></dl>` : ""}
  ${p.dns ? `<h4>DNS</h4><dl class="kv"><dt>Query</dt><dd>${esc(p.dns.qname)} (${esc(p.dns.qtype)})</dd><dt>Response</dt><dd>${p.dns.response ? esc(p.dns.rcode) : "query"}</dd><dt>Answers</dt><dd>${p.dns.answers.map(a => esc(a.type + " " + a.data)).join("<br>") || "—"}</dd></dl>` : ""}
  <h4>Frame bytes</h4><div class="hex">${d.hexdump.map(l => `${l.off}  ${l.hex.padEnd(47)}  <span class="a">${esc(l.ascii)}</span>`).join("\n")}</div>`;
}
async function openPacket(no) { const tok = openDrawer("Packet #" + no, "Re-reading the original evidence file…"); try { const d = await api(A("packets/" + no)); drawerSet(tok, packetBody(d), "Packet #" + no, d.packet.info); } catch (e) { drawerSet(tok, errBox(e)); } }
async function openFlow(fid) {
  const tok = openDrawer("Flow #" + fid, "Reconstructing stream…");
  try {
    const s = await api(A("streams/" + fid)), f = s.flow, d = s.data; let mode = "text";
    const dec = b => { try { return atob(b); } catch { return ""; } };
    const c = dec(d.c), sv = dec(d.s);
    const asText = x => esc(x.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "·"));
    const asHex = x => { let o = ""; for (let i = 0; i < Math.min(x.length, 2048); i += 16) { const ch = x.slice(i, i + 16); o += i.toString(16).padStart(4, "0") + "  " + [...ch].map(k => k.charCodeAt(0).toString(16).padStart(2, "0")).join(" ").padEnd(47) + "  " + asText(ch) + "\n"; } return o; };
    const render = m => `<div class="stream"><div class="c"><b>CLIENT → SERVER (${fmtN(d.c_total)} bytes)</b>\n${m === "text" ? asText(c) : asHex(c)}</div>\n<div class="s"><b>SERVER → CLIENT (${fmtN(d.s_total)} bytes)</b>\n${m === "text" ? asText(sv) : asHex(sv)}</div></div>`;
    const html = `<dl class="kv"><dt>Client</dt><dd>${ipb(f.client)}:${f.cport ?? ""}</dd><dt>Server</dt><dd>${ipb(f.server)}:${f.sport ?? ""} (${esc(f.service || "unknown")})</dd><dt>Application</dt><dd>${esc(f.app || "—")}</dd><dt>State</dt><dd>${esc(f.state)}${f.midstream ? " · captured mid-stream" : ""}${f.gaps ? ` · ${f.gaps} sequence gap(s)` : ""}</dd><dt>Duration</dt><dd>${fmtD(f.duration)}</dd><dt>Packets</dt><dd>${f.c_pkts} client / ${f.s_pkts} server</dd><dt>Payload</dt><dd>${fmtB(f.c_pl)} up / ${fmtB(f.s_pl)} down</dd><dt><button class="btn sm" data-pair="${esc(f.client)}|${esc(f.server)}">All traffic between peers</button></dt><dd></dd></dl>
    ${s.tls.length ? `<h4>TLS metadata</h4>${table([{label: "SNI", render: r => esc(r.sni || "—")}, {label: "Version", render: r => esc(r.version || "—")}, {label: "Negotiated", render: r => esc((r.server_version || "") + " " + (r.cipher || ""))}, {label: "ALPN", render: r => esc(r.alpn || "—")}, {label: "JA3", render: r => `<span class="mono">${esc(r.ja3 || "")}</span>`}], s.tls)}<p style="color:var(--muted)">Payload is encrypted; only handshake metadata is visible.</p>` : ""}
    ${s.http.length ? `<h4>HTTP transactions</h4>${table([{label: "Method", key: "method"}, {label: "Host", key: "host"}, {label: "URI", key: "uri", cls: "wrap"}, {label: "Status", render: r => esc(r.status || "—")}, {label: "Auth", render: r => r.auth_header ? `<span class="tag">${esc(r.auth_scheme || "header")} (value not stored)</span>` : "—"}], s.http)}` : ""}
    <div class="row sb"><h4>Reconstructed conversation</h4><div class="row"><button class="btn sm primary" data-smode="text">Text</button><button class="btn sm" data-smode="hex">Hex</button></div></div><div id="streamBox">${d.c_total + d.s_total ? render("text") : empty("No payload", "<p>This flow carries no application data (handshake only or unanswered probes).</p>")}</div>
    ${d.c_total > 32768 || d.s_total > 32768 ? `<p style="color:var(--muted)">Viewer shows the first 32 KB per direction.</p>` : ""}<h4>Packets</h4>${pktTable(s.packets)}`;
    drawerSet(tok, html, `${f.client} → ${f.server}:${f.sport ?? ""}`, `${f.proto} flow #${fid}`);
    $$("[data-smode]").forEach(b => b.onclick = () => { $$("[data-smode]").forEach(x => x.classList.toggle("primary", x === b)); $("#streamBox").innerHTML = render(b.dataset.smode); });
  } catch (e) { drawerSet(tok, errBox(e)); }
}
async function openPair(a, b) {
  const tok = openDrawer(`${a} ↔ ${b}`, "Communication history");
  try { const p = await api(A(`pair?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`));
    drawerSet(tok, `<dl class="kv"><dt>Flows</dt><dd>${p.flows.length}</dd>${p.edges.map(e => `<dt>${esc(e.s)} → ${esc(e.d)}</dt><dd>${fmtN(e.pkts)} packets · ${fmtB(e.bytes)} · ${Object.keys(e.protos).join(", ")} · ${fmtT(e.first)} → ${fmtT(e.last)}</dd>`).join("")}</dl><h4>Flows</h4>${table([{label: "Client", render: r => ipb(r.client)}, {label: "Server", render: r => ipb(r.server) + ":" + (r.sport ?? "")}, {label: "App", render: r => esc(r.app || r.proto)}, {label: "State", key: "state"}, {label: "Start", render: r => esc(fmtT(r.start).slice(11, 19))}, {label: "Bytes", render: r => fmtB(r.c_bytes + r.s_bytes), cls: "num"}], p.flows.slice(0, 80).map(f => ({...f, _attr: `data-flow="${f.id}"`})), {emptyTitle: "No flows", emptyBody: "Only non-flow traffic (e.g. ARP) exists between these hosts."})}<h4>Packets (first ${p.packets.length})</h4>${pktTable(p.packets)}`); } catch (e) { drawerSet(tok, errBox(e)); }
}
async function openEvidence(id) {
  const tok = openDrawer("Evidence #" + id, "Integrity record");
  const paint = async () => {
    const e = await api("/api/evidence/" + id);
    const st = e.last_verify_status || "pending";
    drawerSet(tok, `<div class="card scan off" id="evScan" style="box-shadow:none;border:1px solid var(--line)"><div class="row sb"><b>${esc(e.filename)}</b><span class="badge-st ${st}">${st === "verified" ? "✓ Verified" : st === "pending" ? "Not yet verified" : st === "mismatch" ? "✗ Hash mismatch" : "✗ File missing"}</span></div><div class="hashscramble" id="hashbox">${esc(e.sha256)}</div><div class="prog" id="vprog" hidden><i></i></div><div class="row"><button class="btn primary" id="btnVerify">${ic("hash")} Re-verify SHA-256</button><a class="btn" href="/api/evidence/${id}/download">${ic("download")} Download original</a>${e.analyses.some(a => a.status === "done") ? "" : `<button class="btn" id="btnAn">${ic("bolt")} Analyze</button>`}</div></div>
    <dl class="kv" style="margin-top:14px"><dt>Case</dt><dd>${esc(e.case_no || "—")}</dd><dt>Size</dt><dd>${fmtB(e.size)} (${fmtN(e.size)} bytes)</dd><dt>Source</dt><dd>${esc(e.source)}</dd><dt>Acquired</dt><dd>${fmtT(e.acquired_at)} by ${esc(e.acquired_by)}</dd><dt>Last verified</dt><dd>${fmtT(e.last_verified_at)}</dd><dt>Stored file</dt><dd>${e.exists ? "present" : "<b style='color:var(--red)'>missing</b>"}</dd><dt>Custody chain</dt><dd>${e.chain.ok ? `<span class="badge-st verified">✓ ${e.chain.entries} entries intact</span>` : `<span class="badge-st mismatch">✗ chain broken at entry ${e.chain.broken_at}</span>`}</dd></dl>
    <h4>Chain of custody</h4><p style="color:var(--muted);margin-top:0">Each entry stores the hash of the previous one, so any edit or deletion is detectable.</p>${table([{label: "Time (UTC)", render: r => esc(fmtT(r.ts))}, {label: "Actor", key: "actor"}, {label: "Action", render: r => `<span class="tag">${esc(r.action)}</span>`}, {label: "Details", key: "details", cls: "wrap"}, {label: "Entry hash", render: r => `<span class="mono">${esc(r.entry_hash.slice(0, 10))}…</span>`}], e.custody)}
    <h4>Analyses</h4>${e.analyses.length ? e.analyses.map(a => `<button class="btn sm" data-select="${a.id}" style="margin:2px">${a.status === "done" ? "Open" : esc(a.status)} analysis #${a.id}</button>`).join("") : "<p>None yet.</p>"}`, "Evidence #" + id, "Integrity record");
    $("#btnVerify").onclick = async () => { const box = $("#hashbox"), pr = $("#vprog"); $("#evScan").classList.remove("off"); pr.hidden = false; $("#btnVerify").disabled = true; const full = e.sha256; let n = 0; const sc = setInterval(() => { box.textContent = [...full].map((ch, i) => i < n ? ch : "0123456789abcdef"[Math.random() * 16 | 0]).join(""); }, 60);
      try { const {job_id} = await api(`/api/evidence/${id}/verify`, {json: {}}); const r = await pollJob(job_id, j => { pr.firstElementChild.style.width = j.progress * 100 + "%"; n = Math.floor(j.progress * 64); }); clearInterval(sc); box.textContent = r.actual || full; toast(r.status === "verified" ? "SHA-256 verified — file is unchanged" : "Integrity check FAILED: " + r.status, r.status === "verified" ? "ok" : "err"); }
      catch (x) { clearInterval(sc); toast(x.message, "err"); } if (drawerOpen) await paint(); refreshStatus(); if (ST.view === "evidence") VIEWS.evidence($("#view")); };
    const an = $("#btnAn"); if (an) an.onclick = () => startAnalysis(id);
  };
  try { await paint(); } catch (e) { drawerSet(tok, errBox(e)); }
}
async function startAnalysis(eid) { try { const {job_id} = await api(`/api/evidence/${eid}/analyze`, {json: {}}); closeDrawer(); location.hash = "#/pcap"; trackJob(job_id, "Analyzing evidence"); } catch (e) { toast(e.message, "err"); } }
async function trackJob(jid, label) {
  ST.busy = {label, progress: 0, stage: "Queued"}; renderPill();
  try { const r = await pollJob(jid, j => { ST.busy = {label, progress: j.progress, stage: j.stage}; renderPill(); const cb = ST.jobUI; cb && cb(j); }); ST.busy = null; renderPill(); await refreshAnalyses(true); if (r && r.analysis_id) { const keep = ST.view === "pcap" && ST.paintBody; await selectAnalysis(r.analysis_id, !!keep); if (keep) ST.paintBody(); renderRight(); toast("Analysis complete", "ok"); } return r; }
  catch (e) { ST.busy = null; renderPill(); toast(e.message, "err"); ST.jobUI && ST.jobUI({status: "error", error: e.message}); refreshStatus(); }
}

// ---------------------------------------------------------------- overview
VIEWS.overview = async root => {
  const has = hasA(), S = has ? ST.ov.summary : null;
  const m = (cls, ico, lab, val, sub, attr = "", hint = "") => `<div class="card metric tilt ${cls} ${attr ? "click" : ""}" ${attr}><span class="ico">${ic(ico)}</span><div class="lab"><span ${hint ? `class="hint" title="${esc(hint)}"` : ""}>${lab}</span></div><div class="val ${typeof val === "number" ? "" : "t"}" ${typeof val === "number" ? `data-count="${val}"` : ""}>${typeof val === "number" ? 0 : val}</div><div class="sub">${sub}</div></div>`;
  const ev = has ? S.evidence : null, sb = has ? S.alerts_by_severity : {};
  const cards = has ? [
    m("", "pkt", "Total Packets Analyzed", S.packets, `${fmtB(S.bytes)} over ${fmtD(S.duration)}`),
    m("", "host", "Unique IP Addresses", S.hosts, Object.entries(S.host_classes || {}).map(([k, v]) => `${v} ${k}`).join(" · ") || "—"),
    m(S.suspicious_connections ? "warn" : "good", "alert", "Suspicious Connections", S.suspicious_connections, "distinct actor → target pairs in findings", "", "Counts unique (actor, target) host pairs that appear together in a detection finding."),
    m("", "grid", "Detected Protocols", Object.keys(S.protocols).length, Object.keys(S.protocols).slice(0, 4).join(", ")),
    m(S.alerts ? (sb.Critical || sb.High ? "bad" : "warn") : "good", "shield", "Threat Indicators", S.alerts, Object.entries(sb).map(([k, v]) => `${v} ${k}`).join(" · ") || "no rule fired"),
    m(ev.status === "verified" ? "good" : "bad", "hash", "Evidence Integrity", ev.status === "verified" ? "Verified" : ev.status === "pending" ? "Pending" : "FAILED", `<span class="mono">${esc(ev.sha256.slice(0, 14))}…</span> ${ev.verified_at ? ago(ev.verified_at) : ""}`, `data-evidence="${ev.id}"`)
  ].join("") : ["Total Packets Analyzed", "Unique IP Addresses", "Suspicious Connections", "Detected Protocols", "Threat Indicators", "Evidence Integrity"].map((l, i) => m("", ["pkt", "host", "alert", "grid", "shield", "hash"][i], l, "—", "Waiting for evidence")).join("");
  root.innerHTML = `<div class="grid g6">${cards}</div>
  <section class="hero"><div class="card globe-card glow ${has && S.case_score >= 60 ? "crit" : ""}" id="globeCard"><canvas id="globeCv"></canvas>
    <div class="globe-top"><div><h3>Live network sphere</h3><p>${has ? `${esc(ev.filename)} · evidence-backed flows only` : "Holographic view of hosts and flows from your capture"}</p></div><div class="row" style="justify-content:flex-end">${has ? `<span class="chip"><i style="color:var(--green)"></i>Investigation active</span><span class="chip sev" style="background:${SEV_COLOR[lvl(S.case_score)] || SEV_COLOR.None}">Threat ${S.case_score} · ${esc(S.case_level)}</span>` : `<span class="chip"><i style="color:#9FB1CC"></i>Idle</span>`}</div></div>
    <div class="globe-legend"><span><i style="background:#2457D6"></i>Located host</span><span><i style="background:#00B5D0"></i>Unlocated (orbit)</span><span><i style="background:#FF9D42"></i>Involved in a finding</span><span>Drag to rotate · click a node</span></div>
    ${has ? "" : `<div class="globe-empty"><div>${ic("pkt")}<b style="display:block;font-size:16px">Waiting for evidence</b><p style="color:var(--muted);margin:4px 0 12px">Nodes, arcs and packets appear here once a capture is analysed. Nothing is simulated.</p><a class="btn primary" href="#/pcap">Upload a capture</a></div></div>`}</div>
    <div class="stack"><div class="card tilt"><h3>Threat radar<small>closer to centre = higher score</small></h3><div class="radar-wrap"><canvas id="radarCv"></canvas></div></div>
    <div class="card tilt"><h3>Traffic waveform<small>${has ? "per " + fmtD(ST.ov.bin_s) : ""}</small></h3>${has ? `<canvas class="wave" id="waveCv"></canvas>` : `<div class="empty" style="padding:20px">Waiting for traffic data</div>`}</div></div></section>
  <div class="grid g21"><div class="card tilt"><h3>Network traffic<small>bytes per interval · hover for values</small></h3><div id="trafficBox" style="height:250px">${has ? "" : empty("No traffic yet", "")}</div></div>
    <div class="card tilt"><h3>Protocol distribution<small>click to filter packets</small></h3><div id="protoBox" style="min-height:250px">${has ? "" : empty("No protocols yet", "")}</div></div></div>
  <div class="grid g21"><div class="card"><h3>Suspicious activity timeline<small>click an event</small></h3><div id="tlBox">${has ? "" : empty("No events", "")}</div></div>
    <div class="card tilt"><h3>Top communicating IPs<small>by bytes</small></h3><div id="topIps">${has ? "" : empty("No hosts", "")}</div></div></div>
  <div class="card"><h3>Recent forensic events</h3><div id="recent">${has ? "" : empty("No forensic events", "Events appear after the first analysis.")}</div></div>`;
  if (!has) return;
  const d = ST.ov; $$("[data-count]", root).forEach(el => countUp(el, el.dataset.count));
  ST.globe = new Globe($("#globeCv"), $("#globeCard"), ip => openIP(ip)); ST.globe.setData(d.graph.nodes, d.graph.edges);
  ST.radar = new Radar($("#radarCv"), ip => openIP(ip)); ST.radar.setData(d.graph.nodes);
  waveform($("#waveCv"), d.series.out_b, d.series.in_b);
  const n = d.series.pkts.length, xf = (i, long) => { const t = d.t0 + i * d.bin_s; return new Date(t * 1000).toISOString().slice(long ? 0 : 11, long ? 19 : 19).replace("T", " "); };
  areaChart($("#trafficBox"), {series: [{name: "Outbound", color: "#00CFE8", data: d.series.out_b}, {name: "Inbound", color: "#2457D6", data: d.series.in_b}, {name: "Internal", color: "#18B887", data: d.series.int_b}], xfmt: xf, yfmt: fmtB, label: "Network traffic over time"});
  donut($("#protoBox"), S.protocols, p => { ST.pktFilter = {proto: p}; location.hash = "#/pcap"; });
  timelineSVG($("#tlBox"), d.timeline.filter(e => e.kind !== "CAPTURE"), d.t0, d.t1, openEvent);
  if (!d.timeline.some(e => e.kind !== "CAPTURE")) $("#tlBox").innerHTML = empty("No suspicious activity", "<p>No detection rule fired on this capture.</p>", "shield");
  $("#topIps").innerHTML = hbars([...d.hosts].sort((a, b) => b.bytes_in + b.bytes_out - a.bytes_in - a.bytes_out).slice(0, 8).map(h => ({label: h.ip, html: `${esc(h.ip)}${h.score ? ` <span class="sev ${h.level}" style="padding:0 6px">${h.score}</span>` : ""}`, value: h.bytes_in + h.bytes_out, attr: `data-ip="${esc(h.ip)}"`})), fmtB); animateBars($("#topIps"));
  $("#recent").innerHTML = table([{label: "Time (UTC)", render: r => esc(fmtT(r.ts).slice(11, 19))}, {label: "Severity", render: r => sev(r.severity)}, {label: "Event", key: "title", cls: "wrap"}, {label: "Actor", render: r => ipb(r.src)}, {label: "Target", render: r => ipb(r.dst)}], [...d.timeline].reverse().slice(0, 8).map(e => ({...e, _attr: `data-event="${e.idx}"`})));
};

// ---------------------------------------------------------------- PCAP analyzer
const STAGES = [["Verifying SHA-256", "Verifying"], ["Parsing packets", "Parsing"], ["Running detection", "Running"], ["Scoring and timeline", "Scoring"], ["Saving analysis", "Saving"]];
function scanAnim(cv) {
  const [c0] = setupCanvas(cv); let pk = [], dead = false, t = 0;
  (function f() { if (dead || !cv.isConnected) return; const [c, W, H] = setupCanvas(cv); c.clearRect(0, 0, W, H); t += 1;
    if (!REDUCED && t % 5 === 0) pk.push({x: -20, y: 20 + Math.random() * (H - 50), w: 10 + Math.random() * 24, v: 1.6 + Math.random() * 1.4, c: Math.random()});
    const gx = W * .55; const g = c.createLinearGradient(gx - 30, 0, gx + 30, 0); g.addColorStop(0, "rgba(0,207,232,0)"); g.addColorStop(.5, "rgba(0,207,232,.35)"); g.addColorStop(1, "rgba(0,207,232,0)"); c.fillStyle = g; c.fillRect(gx - 30, 0, 60, H); c.fillStyle = "#00CFE8"; c.fillRect(gx - 1, 0, 2, H);
    pk = pk.filter(p => p.x < W + 30); for (const p of pk) { p.x += p.v; const scanned = p.x > gx; c.fillStyle = scanned ? (p.c > .85 ? "#FF9D42" : "#18B887") : "#2457D6"; c.globalAlpha = scanned ? .85 : .55; c.beginPath(); c.roundRect(p.x, p.y, p.w, 9, 3); c.fill(); c.globalAlpha = 1; }
    requestAnimationFrame(f); })();
  return () => dead = true;
}
VIEWS.pcap = async root => {
  const cases = await api("/api/cases").catch(() => []);
  root.innerHTML = pageHead("PCAP Analyzer", "Upload a PCAP/PCAPNG capture. Its SHA-256 is recorded on arrival, re-checked before analysis, and every step is written to the chain of custody.") +
    `<div class="grid g21"><div class="card tilt no-tilt" id="upCard"><label class="drop" id="drop" tabindex="0">${ic("up")}<b style="display:block;font-size:17px;margin:6px 0 2px">Drop a capture here or click to browse</b><span style="color:var(--muted)">.pcap · .pcapng · .cap — processed locally, nothing leaves this machine</span><input type="file" id="file" accept=".pcap,.pcapng,.cap"></label>
      <div class="row" style="margin-top:12px"><div class="field" style="margin:0;flex:1;min-width:200px"><label for="caseSel">Case</label><select id="caseSel"><option value="">Create a new case automatically</option>${cases.map(c => `<option value="${c.id}">${esc(c.case_no)} — ${esc(c.title)}</option>`).join("")}</select></div></div>
      <div id="proc" hidden><div class="scan" style="border-radius:14px;background:#F4F9FF;margin-top:14px"><canvas id="scanCv" style="width:100%;height:96px;display:block"></canvas></div><div class="row sb" style="margin-top:8px"><b id="procName"></b><span id="procPct" class="mono"></span></div><div class="prog"><i id="procBar"></i></div><ul class="ladder" id="ladder"><li data-s="upload"><i></i>Uploading and hashing evidence</li>${STAGES.map(([l], i) => `<li data-s="${i}"><i></i>${l}</li>`).join("")}</ul><div id="procErr"></div></div></div>
    <div class="card tilt"><h3>What happens to your file</h3><ol style="padding-left:18px;margin:0;line-height:1.9"><li>Stored read-only in the evidence folder with its SHA-256.</li><li>Hash re-verified immediately before analysis.</li><li>Packets parsed (Ethernet, ARP, IPv4/6, TCP, UDP, ICMP, DNS) and TCP streams reassembled.</li><li>TLS handshakes, HTTP and DNS metadata extracted.</li><li>Detection rules run and scored; each finding cites packets.</li></ol><p style="color:var(--muted)">HTTPS content is never decrypted.</p></div></div>
    <div id="pcapBody"></div>`;
  const drop = $("#drop"), fi = $("#file");
  ["dragenter", "dragover"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); })); ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => { if (e.dataTransfer.files[0]) doUpload(e.dataTransfer.files[0]); }); fi.onchange = () => fi.files[0] && doUpload(fi.files[0]); drop.onkeydown = e => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), fi.click());
  function doUpload(file) {
    $("#proc").hidden = false; $("#procName").textContent = `${file.name} · ${fmtB(file.size)}`; $("#procErr").innerHTML = ""; const stop = scanAnim($("#scanCv")); const bar = $("#procBar"), pct = $("#procPct");
    const mark = (k, st) => { const li = $(`.ladder [data-s="${k}"]`); if (li) li.className = st; };
    $$(".ladder li").forEach(l => l.className = ""); mark("upload", "on");
    const fd = new FormData(); fd.append("file", file); if ($("#caseSel").value) fd.append("case_id", $("#caseSel").value);
    const x = new XMLHttpRequest(); x.open("POST", "/api/upload"); x.upload.onprogress = e => { if (e.lengthComputable) { bar.style.width = (e.loaded / e.total * 20) + "%"; pct.textContent = Math.round(e.loaded / e.total * 100) + "% uploaded"; } };
    x.onerror = () => { stop(); $("#procErr").innerHTML = errBox(new Error("Upload failed - is the server running?")); };
    x.onload = async () => { let r = {}; try { r = JSON.parse(x.responseText); } catch {} if (x.status >= 400) { stop(); mark("upload", ""); $("#procErr").innerHTML = errBox(new Error(r.error || "Upload rejected")); return; }
      mark("upload", "done"); toast("Evidence stored · SHA-256 " + r.sha256.slice(0, 12) + "…", "ok");
      ST.jobUI = j => { if (j.status === "error") { stop(); $("#procErr").innerHTML = errBox(new Error(j.error)); $$(".ladder li.on").forEach(l => l.className = ""); return; } const idx = STAGES.findIndex(([, k]) => j.stage.startsWith(k)); STAGES.forEach((_, i) => mark(i, i < idx ? "done" : i === idx ? "on" : "")); bar.style.width = 20 + j.progress * 80 + "%"; pct.textContent = Math.round(j.progress * 100) + "% · " + j.stage; if (j.status === "done") { STAGES.forEach((_, i) => mark(i, "done")); stop(); pct.textContent = "Complete"; } };
      await trackJob(r.job_id, file.name); ST.jobUI = null; };
    x.send(fd);
  }
  const paintBody = async () => {
    const b = $("#pcapBody"); if (!hasA()) { b.innerHTML = ""; return; } const S = ST.ov.summary, f = ST.pktFilter || {}; ST.pktFilter = null;
    b.innerHTML = `<div class="card"><h3>Packet explorer<small>${esc(S.evidence.filename)} · ${fmtN(S.packets)} packets</small></h3><div class="row" style="margin-bottom:12px"><input class="input" id="pq" placeholder="Filter: IP, port, protocol or text in info" style="max-width:340px" value="${esc(f.q || "")}"><select class="input" id="pp" style="max-width:180px"><option value="">All protocols</option>${Object.keys(S.protocols).map(p => `<option ${f.proto === p ? "selected" : ""}>${esc(p)}</option>`).join("")}</select><span id="pcount" style="color:var(--muted)"></span><span style="margin-left:auto" class="row"><button class="btn sm" id="pprev">Previous</button><button class="btn sm" id="pnext">Next</button></span></div><div id="ptable">${loading()}</div></div>`;
    let page = 0; const load = async () => { try { const d = await api(A(`packets?page=${page}&size=100&q=${encodeURIComponent($("#pq").value)}&proto=${encodeURIComponent($("#pp").value)}`)); $("#ptable").innerHTML = pktTable(d.rows); $("#pcount").textContent = `${fmtN(d.total)} packets · page ${page + 1}/${Math.max(1, Math.ceil(d.total / 100))}`; $("#pprev").disabled = page === 0; $("#pnext").disabled = (page + 1) * 100 >= d.total; } catch (e) { $("#ptable").innerHTML = errBox(e); } };
    let tm; $("#pq").oninput = () => { clearTimeout(tm); tm = setTimeout(() => { page = 0; load(); }, 250); }; $("#pp").onchange = () => { page = 0; load(); }; $("#pprev").onclick = () => { page--; load(); }; $("#pnext").onclick = () => { page++; load(); }; load();
  };
  ST.paintBody = paintBody; if (hasA()) paintBody();
};

// ---------------------------------------------------------------- live monitoring
VIEWS.live = async root => {
  root.innerHTML = pageHead("Live Network Monitoring", "Captures real packets from a network interface on this machine into a PCAP evidence file. Counters below are computed only from packets actually received.") + loading();
  let cap; try { cap = await api("/api/live/status"); } catch (e) { root.innerHTML += errBox(e); return; }
  const c = cap.capability;
  if (!c.available) { root.innerHTML = pageHead("Live Network Monitoring", "Captures real packets from a network interface on this machine.") + `<div class="card">${empty("Live capture is unavailable here", `<p style="max-width:60ch;margin:auto">${esc(c.reason)}</p>`, "live", `<a class="btn" href="#/pcap">Upload a recorded capture instead</a>`)}</div>`; return; }
  root.innerHTML = pageHead("Live Network Monitoring", `Backend: <b>${esc(c.backend)}</b>. Packets are written to an evidence file; stopping seals it with a SHA-256 and a chain-of-custody entry.`) +
    `<div class="card tilt no-tilt" style="margin-bottom:14px"><div class="row" id="ctrl"><div class="field" style="margin:0"><label for="lif">Interface</label><select id="lif" class="input">${c.interfaces.map(i => `<option value="${esc(i.name)}">${esc(i.name)}${i.state ? " (" + esc(i.state) + ")" : ""}</option>`).join("")}</select></div><div class="field" style="margin:0"><label for="lsec">Stop after (seconds, 0 = manual)</label><input id="lsec" class="input" type="number" min="0" value="0"></div><div class="field" style="margin:0"><label for="lmax">Max packets (0 = unlimited)</label><input id="lmax" class="input" type="number" min="0" value="0"></div>
      <button class="btn primary" id="lstart" style="margin-top:18px">${ic("play")} Start capture</button><button class="btn warn" id="lstop" style="margin-top:18px" hidden>${ic("stop")} Stop &amp; analyze</button><button class="btn" id="lsnap" style="margin-top:18px" hidden>${ic("bolt")} Analyze snapshot</button></div><div id="lerr"></div></div><div id="liveBody"></div>`;
  const body = $("#liveBody"); let wf = null;
  const paint = s => {
    $("#lstart").hidden = s.running; $("#lstop").hidden = $("#lsnap").hidden = !s.running; $$("#ctrl select,#ctrl input").forEach(i => i.disabled = s.running);
    if (!s.started) { body.innerHTML = `<div class="card">${empty("Not capturing", "<p>Choose an interface and start. Nothing is shown until packets arrive.</p>", "live")}</div>`; return; }
    if (!$("#lpk")) body.innerHTML = `<div class="grid g4"><div class="card metric tilt"><div class="lab">Packets</div><div class="val" id="lpk">0</div><div class="sub" id="lpps"></div></div><div class="card metric tilt"><div class="lab">Bytes</div><div class="val" id="lby">0</div><div class="sub" id="lbps"></div></div><div class="card metric tilt"><div class="lab">Elapsed</div><div class="val" id="lel">0</div><div class="sub" id="lst"></div></div><div class="card metric tilt"><div class="lab">Evidence file</div><div class="sub mono" id="lfile" style="word-break:break-all"></div></div></div>
      <div class="grid g21"><div class="card"><h3>Live traffic<small>bytes per second</small></h3><canvas class="wave" id="lw" style="height:150px"></canvas></div><div class="card"><h3>Protocols</h3><div id="lprot"></div></div></div><div class="grid g3"><div class="card"><h3>Top talkers</h3><div id="ltalk"></div></div><div class="card"><h3>DNS names seen</h3><div id="ldns"></div></div><div class="card"><h3>Status</h3><div id="lstatus"></div></div></div><div class="card"><h3>Recent packets</h3><div id="lrecent"></div></div>`;
    countUp($("#lpk"), s.packets, fmtN, 400); $("#lpps").textContent = s.pps + " packets/s"; countUp($("#lby"), s.bytes, fmtB, 400); $("#lbps").textContent = fmtN(s.bps) + " bit/s"; $("#lel").textContent = fmtD(s.duration); $("#lst").innerHTML = s.running ? `<i class="dot live" style="display:inline-block"></i> capturing on ${esc(s.iface)}` : "stopped"; $("#lfile").textContent = s.path ? s.path.split("/").pop() : "";
    const ser = s.series; if (ser.length > 1) { wf && wf.stop(); wf = waveform($("#lw"), ser.map(x => x.out + x.int), ser.map(x => x.in + x.oth), false); }
    $("#lprot").innerHTML = hbars(Object.entries(s.protocols).map(([k, v]) => ({label: k, value: v}))); animateBars($("#lprot"), true);
    $("#ltalk").innerHTML = hbars(s.talkers.map(([ip, b]) => ({label: ip, html: esc(ip), value: b, attr: ""})), fmtB); animateBars($("#ltalk"), true);
    $("#ldns").innerHTML = s.dns.length ? hbars(s.dns.map(([n, v]) => ({label: n, value: v}))) : `<p style="color:var(--muted)">No DNS queries seen yet.</p>`; animateBars($("#ldns"), true);
    $("#lstatus").innerHTML = s.error ? errBox(new Error(s.error)) : `<p style="margin:0">${s.running ? "Capture running. Use <b>Analyze snapshot</b> to run the full detection engine on what has been captured so far without stopping." : "Capture finished."}</p>`;
    $("#lrecent").innerHTML = pktTable(s.recent.slice().reverse().map(r => ({...r, _attr: ""})));
  };
  const poll = async () => { try { const r = await api("/api/live/status"); ST.live = r.session; paint(r.session); renderPill(); } catch {} };
  $("#lstart").onclick = async () => { try { $("#lerr").innerHTML = ""; await api("/api/live/start", {json: {iface: $("#lif").value, max_seconds: +$("#lsec").value, max_packets: +$("#lmax").value}}); toast("Capture started on " + $("#lif").value, "ok"); poll(); } catch (e) { $("#lerr").innerHTML = errBox(e); } };
  $("#lstop").onclick = async () => { try { const r = await api("/api/live/stop", {json: {analyze: true}}); await poll(); if (!r.evidence_id) return toast(r.message); toast("Capture sealed as evidence #" + r.evidence_id, "ok"); trackJob(r.job_id, "Analyzing live capture"); } catch (e) { toast(e.message, "err"); } };
  $("#lsnap").onclick = async () => { try { const r = await api("/api/live/snapshot", {json: {}}); toast("Snapshot stored as evidence #" + r.evidence_id, "ok"); trackJob(r.job_id, "Analyzing snapshot"); } catch (e) { toast(e.message, "err"); } };
  paint(cap.session); ST.live = cap.session; ST.timers.push(setInterval(poll, 1000)); ST.cleanup = () => wf && wf.stop();
};
