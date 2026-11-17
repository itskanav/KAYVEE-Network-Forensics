"use strict";
const NAV = [["overview", "Overview", "grid"], ["pcap", "PCAP Analyzer", "file"], ["live", "Live Network Monitoring", "live"], ["ip", "IP Intelligence", "ip"], ["threat", "Threat Detection", "shield"], ["dns", "DNS Investigation", "dns"], ["tcp", "TCP Stream Analysis", "tcp"], ["map", "Network Mapping", "map"], ["timeline", "Attack Timeline", "time"], ["evidence", "Evidence Manager", "box"], ["cases", "Case Management", "case"], ["reports", "Investigation Reports", "report"], ["settings", "Settings", "gear"]];

function renderSide() {
  const bad = hasA() ? ST.ov.alerts.filter(a => a.severity === "Critical" || a.severity === "High").length : 0;
  $("#side").innerHTML = NAV.map(([k, l, i], n) => `${n === 3 || n === 9 || n === 12 ? "<hr>" : ""}<a class="nav ${ST.view === k ? "active" : ""}" href="#/${k}" title="${esc(l)}" ${ST.view === k ? 'aria-current="page"' : ""}>${ic(i)}<span>${l}</span>${k === "threat" && bad ? `<em class="badge">${bad}</em>` : ""}</a>`).join("");
}
function renderPill() {
  const t = $("#invText"), d = $("#invPill .dot"); let txt = "No investigation", cls = "idle";
  if (ST.live && ST.live.running) { txt = `Live capture · ${fmtN(ST.live.packets)} packets`; cls = "live"; }
  else if (ST.busy) { txt = `${ST.busy.stage} · ${Math.round(ST.busy.progress * 100)}%`; cls = "busy"; }
  else if (hasA()) { const s = ST.ov.summary; txt = `${s.evidence.filename} · ${s.case_level === "None" ? "no findings" : s.case_level + " " + s.case_score}`; cls = "ok"; }
  t.textContent = txt; d.className = "dot " + cls;
}
async function refreshStatus() {
  try { ST.status = await api("/api/status"); $("#analystName").textContent = ST.status.analyst; $("#avatar").textContent = (ST.status.analyst[0] || "A").toUpperCase(); const n = ST.status.counts.unread; $("#bellCount").hidden = !n; $("#bellCount").textContent = n > 99 ? "99+" : n; } catch {}
}
async function refreshAnalyses(quiet) { try { ST.analyses = await api("/api/analyses"); } catch (e) { !quiet && toast(e.message, "err"); } }
async function selectAnalysis(aid, noRender) {
  if (!aid) { ST.aid = ST.ov = null; } else {
    try { ST.ov = await api(`/api/analyses/${aid}/overview`); ST.aid = aid; store.set("kv-aid", aid); } catch (e) { toast("Could not load analysis: " + e.message, "err"); ST.aid = ST.ov = null; }
  }
  renderPill(); renderSide(); renderRight(); if (!noRender) route(true);
}

// ---------------------------------------------------------------- right intelligence panel
function renderRight() {
  const R = $("#right");
  if (!hasA()) { R.innerHTML = `<div class="card tilt"><h3>Investigation intelligence</h3>${empty("Waiting for evidence", "<p>Alerts, severity, suspicious hosts and recommendations will appear here after an analysis.</p>", "shield")}</div>`; return; }
  const d = ST.ov, S = d.summary, al = d.alerts, sb = S.alerts_by_severity, tot = Math.max(1, S.alerts);
  const sus = [...d.hosts].filter(h => h.score > 0).sort((a, b) => b.score - a.score).slice(0, 4);
  R.innerHTML = `<div class="card glow ${S.case_score >= 60 ? "crit" : ""}"><h3>Threat severity</h3><div class="sev-gauge"><div class="score-ring" style="--p:0;--c:${SEV_COLOR[lvl(S.case_score)]}" id="gauge"><span>${S.case_score}</span></div><div><div>${S.case_level === "None" ? `<span class="sev None">No findings</span>` : sev(S.case_level)}</div><p style="margin:6px 0 0;color:var(--muted);font-size:12.5px">Combined score of the strongest findings. Indicators, not proof.</p></div></div><div class="sevbar" style="margin-top:12px">${["Critical", "High", "Medium", "Low", "Info"].map(k => `<i style="width:${(sb[k] || 0) / tot * 100}%;background:${SEV_COLOR[k]}" title="${k}: ${sb[k] || 0}"></i>`).join("")}</div><div class="row" style="margin-top:8px;gap:6px">${["Critical", "High", "Medium", "Low"].map(k => sb[k] ? `<span class="tag" style="color:${SEV_COLOR[k] === "#E8B029" ? "#8A6A00" : SEV_COLOR[k]}">${sb[k]} ${k}</span>` : "").join("") || `<span style="color:var(--muted)">Nothing flagged</span>`}</div></div>
  <div class="card"><h3>Latest alerts<small><a href="#/threat">view all</a></small></h3>${al.length ? al.slice(0, 5).map(alertCard).join("") : empty("No alerts", "<p>No detection rule fired.</p>", "shield")}</div>
  <div class="card"><h3>Suspicious IPs</h3>${sus.length ? sus.map(h => `<button class="alert" data-ip="${esc(h.ip)}"><span class="bar" style="background:${SEV_COLOR[h.level]}"></span><span><b class="mono">${esc(h.ip)}</b><small>${esc(h.names[0] || (h.geo ? [h.geo.city, h.geo.country].filter(Boolean).join(", ") : h.class + (h.class === "public" ? " · unlocated" : "")))} · ${h.alerts.length} finding(s)</small></span><span>${sev(h.level)}</span></button>`).join("") : empty("No suspicious hosts", "", "host")}</div>
  <div class="card"><h3>Recommendations</h3>${d.recommendations.length ? `<ol style="padding-left:18px;margin:0">${d.recommendations.map(r => `<li style="margin-bottom:8px"><button class="ip" data-alert="${esc(r.alert)}" style="font-weight:700;color:var(--ink)">${esc(r.title)}</button><br><small style="color:var(--muted)">${esc(r.action)}</small></li>`).join("")}</ol>` : `<p style="color:var(--muted);margin:0">Nothing to recommend. Consider loading an IOC list or widening the capture window.</p>`}</div>
  <div class="card"><h3>Ask the local analyst<small>rule-based · offline</small></h3><div class="row" style="flex-wrap:nowrap"><input class="input" id="askq" placeholder="e.g. riskiest host, explain A-001" aria-label="Question"><button class="btn primary sm" id="askgo">Ask</button></div><div id="askout" style="margin-top:10px;font-size:13px"></div><p style="font-size:11.5px;color:var(--muted);margin:8px 0 0">${esc(d.narrative)}</p></div>`;
  requestAnimationFrame(() => { const g = $("#gauge"); g && g.style.setProperty("--p", S.case_score); });
  const ask = async () => { const q = $("#askq").value.trim(); if (!q) return; $("#askout").innerHTML = loading(); try { const r = await api(A("ask"), {json: {q}}); $("#askout").innerHTML = `<div class="note info">${esc(r.answer)}</div>${r.refs.map(x => `<button class="tag" style="border:0;cursor:pointer" data-${x.type === "ip" ? "ip" : "alert"}="${esc(x.value)}">${esc(x.value)}</button>`).join("")}`; } catch (e) { $("#askout").innerHTML = errBox(e); } };
  $("#askgo").onclick = ask; $("#askq").onkeydown = e => e.key === "Enter" && ask();
}

// ---------------------------------------------------------------- routing
async function route(force) {
  const name = (location.hash.match(/^#\/(\w+)/) || [])[1] || "overview"; const v = VIEWS[name] ? name : "overview";
  if (v === ST.view && !force) return;
  clearTimers(); ST.view = v; renderSide();
  const root = $("#view"); root.classList.remove("enter"); root.innerHTML = loading(); root.scrollTop = 0;
  try { await VIEWS[v](root); } catch (e) { console.error(e); root.innerHTML = pageHead("Something went wrong", "") + errBox(e); }
  if (ST.view === v) { void root.offsetWidth; root.classList.add("enter"); if (!REDUCED) setTimeout(() => root.classList.remove("enter"), 900); wireAcc(root); root.focus({preventScroll: true}); }
}

// ---------------------------------------------------------------- search, notifications, menus
function buildSearch(q) {
  q = q.toLowerCase().trim(); const box = $("#sresults"); if (!q) { box.hidden = true; return; }
  const out = [];
  if (hasA()) { const d = ST.ov;
    d.hosts.filter(h => h.ip.includes(q) || h.names.some(n => n.toLowerCase().includes(q))).slice(0, 5).forEach(h => out.push(`<button data-ip="${esc(h.ip)}">${ic("host")}<span class="mono">${esc(h.ip)}</span><small>${esc(h.names[0] || h.class)}</small></button>`));
    d.alerts.filter(a => a.id.toLowerCase() === q || a.title.toLowerCase().includes(q) || a.category.toLowerCase().includes(q)).slice(0, 5).forEach(a => out.push(`<button data-alert="${esc(a.id)}">${ic("alert")}<span>${esc(a.title)}</span><small>${esc(a.id)}</small></button>`));
    d.dns.top_domains.filter(([n]) => n.includes(q)).slice(0, 3).forEach(([n, c]) => out.push(`<button data-go="dns">${ic("dns")}<span>${esc(n)}</span><small>${c} queries</small></button>`));
    out.push(`<button data-pktsearch="${esc(q)}">${ic("search")}<span>Search packets for “${esc(q)}”</span></button>`);
  } else out.push(`<button disabled>${ic("alert")}<span>Load an investigation to search it</span></button>`);
  box.innerHTML = out.join(""); box.hidden = false;
}
async function openBell() {
  const m = $("#bellMenu"); if (!m.hidden) { m.hidden = true; return; } m.innerHTML = loading(); m.hidden = false; $("#invMenu").hidden = true;
  try { const n = await api("/api/notifications"); m.innerHTML = `<div class="row sb" style="padding:6px 10px"><b>Notifications</b><button class="btn sm" id="markread">Mark all read</button></div>` + (n.length ? n.slice(0, 25).map(x => `<button class="mi ${x.read ? "" : "unread"}" data-notif='${esc(JSON.stringify({t: x.ref_type, r: x.ref_id, a: x.analysis_id}))}'><span class="sev ${({critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info"})[x.level] || "Info"}">${esc(x.level)}</span> <b>${esc(x.title)}</b><small>${esc(x.body)} · ${ago(x.ts)}</small></button>`).join("") : empty("No notifications", "<p>Alerts for new findings, failed integrity checks and finished analyses appear here.</p>", "alert"));
    $("#markread") && ($("#markread").onclick = async () => { await api("/api/notifications", {json: {}}); refreshStatus(); openBell(); openBell(); }); } catch (e) { m.innerHTML = errBox(e); }
}
function openInv() {
  const m = $("#invMenu"); if (!m.hidden) { m.hidden = true; return; } $("#bellMenu").hidden = true;
  const done = ST.analyses.filter(a => a.status === "done");
  m.innerHTML = `<div style="padding:6px 10px"><b>Investigations</b></div>` + (done.length ? done.map(a => `<button class="mi" data-select="${a.id}">${a.id === ST.aid ? "● " : ""}<b>${esc(a.filename)}</b><small>${esc(a.case_no || "")} · ${fmtN(a.summary.packets)} packets · ${a.summary.alerts} findings · ${ago(a.created)}</small></button>`).join("") : empty("None yet", "<p>Upload a capture to start an investigation.</p>", "case")) + `<a class="mi" href="#/pcap" style="text-decoration:none;color:inherit">${ic("up")} New investigation…</a>`; m.hidden = false;
}

document.addEventListener("click", async e => {
  const t = e.target.closest("[data-ip],[data-alert],[data-event],[data-pkt],[data-flow],[data-pair],[data-evidence],[data-select],[data-triage],[data-addnote],[data-go],[data-pktsearch],[data-notif]"); 
  if (!e.target.closest(".search")) $("#sresults").hidden = true; if (!e.target.closest("#bellMenu,#bell")) $("#bellMenu").hidden = true; if (!e.target.closest("#invMenu,#invPill")) $("#invMenu").hidden = true;
  if (!t) return; const d = t.dataset;
  if (t.tagName === "BUTTON" && t.closest("#sresults,#bellMenu,#invMenu")) { $("#sresults").hidden = $("#bellMenu").hidden = $("#invMenu").hidden = true; }
  if (d.ip) return openIP(d.ip);
  if (d.alert) return openAlert(d.alert);
  if (d.event) return openEvent(ST.ov.timeline.find(x => x.idx == d.event));
  if (d.pkt) return openPacket(+d.pkt);
  if (d.flow) return openFlow(+d.flow);
  if (d.pair) { const [a, b] = d.pair.split("|"); return openPair(a, b); }
  if (d.evidence) return openEvidence(+d.evidence);
  if (d.select) { await selectAnalysis(+d.select); closeDrawer(); return toast("Investigation loaded", "ok"); }
  if (d.go) { location.hash = "#/" + d.go; return; }
  if (d.pktsearch) { ST.pktFilter = {q: d.pktsearch}; location.hash = "#/pcap"; route(true); return; }
  if (d.notif) { const n = JSON.parse(d.notif); if (n.a && n.a !== ST.aid) await selectAnalysis(n.a, true); if (n.t === "alert" && n.a) { await route(true); return openAlert(n.r); } if (n.t === "evidence") return openEvidence(+n.r); if (n.a) { await route(true); } return; }
  if (d.triage) { try { const r = await api(`/api/analyses/${ST.aid}/alerts/${d.aid}`, {method: "PATCH", json: {status: d.triage}}); $$("[data-triage]").forEach(b => b.classList.toggle("primary", b.dataset.triage === d.triage)); const a = ST.ov.alerts.find(x => x.id === d.aid); a && (a.status = d.triage); toast("Marked " + d.triage.replace("-", " "), "ok"); } catch (x) { toast(x.message, "err"); } return; }
  if (d.addnote) { const ref = d.addnote, ta = $(`[data-noteref="${CSS.escape(ref)}"]`), text = ta.value.trim(); if (!text) return toast("Write a note first"); const isCase = ref.startsWith("case-");
    try { const n = await api("/api/notes", {json: {case_id: isCase ? +ref.slice(5) : ST.ov.case_id, analysis_id: isCase ? null : ST.aid, ref: isCase ? "" : ref, text}}); ta.value = ""; toast("Note saved", "ok"); const list = $(`#notes-${CSS.escape(ref)}`); if (list) { if (list.querySelector("p")) list.innerHTML = ""; list.insertAdjacentHTML("beforeend", noteList([n])); } else if (isCase) VIEWS.cases($("#view")); } catch (x) { toast(x.message, "err"); } }
});
document.addEventListener("keydown", e => { if (e.key === "Escape") { if (drawerOpen) closeDrawer(); $("#sresults").hidden = $("#bellMenu").hidden = $("#invMenu").hidden = true; } });
$("#scrim").onclick = $("#drClose").onclick = closeDrawer;
$("#navToggle").onclick = () => { $(".app").classList.toggle("collapsed"); store.set("kv-collapsed", $(".app").classList.contains("collapsed")); };
$("#bell").onclick = openBell; $("#invPill").onclick = openInv;
$("#analystBtn").onclick = () => location.hash = "#/settings";
$("#gsearch").oninput = e => buildSearch(e.target.value); $("#gsearch").onfocus = e => buildSearch(e.target.value);
$("#gsearch").onkeydown = e => { if (e.key === "Enter") { const first = $("#sresults button:not([disabled])"); first && first.click(); } };
addEventListener("hashchange", () => route());

// ---------------------------------------------------------------- boot
async function boot() {
  $("#app").hidden = false; if (store.get("kv-collapsed", innerWidth < 1100)) $(".app").classList.add("collapsed");
  renderSide(); renderRight(); await refreshStatus(); await refreshAnalyses(true);
  const done = ST.analyses.filter(a => a.status === "done"), saved = store.get("kv-aid", null), pick = done.find(a => a.id === saved) || done[0];
  if (pick) await selectAnalysis(pick.id, true);
  await route(true);
  setInterval(refreshStatus, 15000);
  setInterval(async () => { if (ST.live && !ST.live.running && ST.view !== "live") return; try { const r = await api("/api/live/status"); ST.live = r.session; renderPill(); } catch {} }, 4000);
}
playIntro(boot);
