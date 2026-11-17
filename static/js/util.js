"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const SEV_COLOR = {Critical: "#E94B64", High: "#FF9D42", Medium: "#E8B029", Low: "#00CFE8", Info: "#8DA2C0", None: "#18B887"};
const ICON = {
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z", file: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6", live: "M3 12h4l2-6 4 12 2-6h6", ip: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", dns: "M4 6h16M4 12h16M4 18h10M18 17l2 2 3-4", tcp: "M4 8h12l-3-3M20 16H8l3 3", map: "M12 3v4M12 17v4M3 12h4M17 12h4M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z", time: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  box: "M4 8l8-4 8 4v8l-8 4-8-4zM4 8l8 4 8-4M12 12v8", case: "M4 8h16v11H4zM9 8V5h6v3", report: "M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h3", gear: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19 12l2-1-1-3-2 .5-1.5-1.5.5-2-3-1-1 2h-2l-1-2-3 1 .5 2L6 8.500 4 8l-1 3 2 1v2l-2 1 1 3 2-.5L7.500 19l-.5 2 3 1 1-2h2l1 2 3-1-.5-2L18 17.500l2 .5 1-3-2-1z",
  chev: "M6 9l6 6 6-6", up: "M12 19V5M5 12l7-7 7 7", alert: "M12 4l9 16H3zM12 10v4M12 17v.5", pkt: "M3 7l9-4 9 4-9 4zM3 7v10l9 4 9-4V7", host: "M3 5h18v10H3zM8 19h8M12 15v4", check: "M5 12l5 5 9-10", bolt: "M13 3L5 14h6l-1 7 8-11h-6z",
  hash: "M5 9h14M5 15h14M9 4L7 20M17 4l-2 16", search: "M11 5a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM16 16l4 4", download: "M12 4v11M7 11l5 5 5-5M5 20h14", play: "M7 5l12 7-12 7z", stop: "M6 6h12v12H6z", plus: "M12 5v14M5 12h14", empty: "M4 7l8-4 8 4v10l-8 4-8-4zM4 7l8 4 8-4M12 11v10"
};
const ic = (n, cls = "") => `<svg viewBox="0 0 24 24" class="${cls}"><path d="${ICON[n] || ICON.grid}"/></svg>`;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const fmtN = n => (n ?? 0).toLocaleString("en-US");
const fmtB = n => { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(n >= 100 ? 0 : 1) : n) + " " + u[i]; };
const fmtT = (t, ms) => t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, ms ? 23 : 19) + " UTC" : "—";
const fmtD = s => s < 1 ? (s * 1000).toFixed(0) + " ms" : s < 120 ? s.toFixed(1) + " s" : s < 7200 ? (s / 60).toFixed(1) + " min" : (s / 3600).toFixed(1) + " h";
const ago = t => { const d = Date.now() / 1000 - t; return d < 60 ? "just now" : d < 3600 ? Math.floor(d / 60) + " min ago" : d < 86400 ? Math.floor(d / 3600) + " h ago" : Math.floor(d / 86400) + " d ago"; };
const sev = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const isIP = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s || "") || (/^[0-9a-f:]+$/i.test(s || "") && (s.match(/:/g) || []).length >= 2 && ((s.match(/:/g) || []).length !== 5 || s.includes("::")));
const ipb = ip => isIP(ip) ? `<button class="ip" data-ip="${esc(ip)}">${esc(ip)}</button>` : esc(ip || "—");
const lvl = sc => sc >= 80 ? "Critical" : sc >= 60 ? "High" : sc >= 35 ? "Medium" : sc > 0 ? "Low" : "None";
const store = { get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} } };

async function api(path, opts = {}) {
  const o = {method: opts.method || "GET", headers: {}};
  if (opts.json !== undefined) { o.body = JSON.stringify(opts.json); o.headers["Content-Type"] = "application/json"; if (o.method === "GET") o.method = "POST"; }
  let r;
  try { r = await fetch(path, o); } catch (e) { throw new Error("Cannot reach the KAYVEE server. Is it still running?"); }
  let d = null;
  try { d = await r.json(); } catch {}
  if (!r.ok) throw new Error((d && d.error) || `Request failed (${r.status})`);
  if (d === null) throw new Error("The server sent an unreadable response. Please retry.");
  return d;
}
function toast(msg, kind = "") {
  const t = document.createElement("div"); t.className = "toast " + kind; t.textContent = msg; $("#toasts").appendChild(t);
  setTimeout(() => { t.style.transition = "opacity .4s"; t.style.opacity = 0; setTimeout(() => t.remove(), 450); }, kind === "err" ? 6500 : 3200);
}
async function pollJob(jid, onUpdate) {
  for (;;) {
    const j = await api("/api/jobs/" + jid);
    onUpdate && onUpdate(j);
    if (j.status !== "running") { if (j.status === "error") throw new Error(j.error); return j.result; }
    await new Promise(r => setTimeout(r, 250));
  }
}
const loading = (msg = "Loading") => `<div class="holo-load" role="status" aria-label="${msg}"><i></i></div>`;
const empty = (title, body, icon = "empty", action = "") => `<div class="empty">${ic(icon)}<b>${esc(title)}</b>${body}${action ? `<div style="margin-top:12px">${action}</div>` : ""}</div>`;
const errBox = e => `<div class="err" role="alert"><b>Something went wrong.</b> ${esc(e.message || e)}</div>`;

// drawer
let drawerOpen = false, drawerToken = 0, lastFocus = null;
function openDrawer(title, sub, html) {
  lastFocus = document.activeElement;
  $("#drTitle").textContent = title; $("#drSub").textContent = sub || ""; $("#drBody").innerHTML = html ?? loading();
  $("#drawer").hidden = $("#scrim").hidden = false; drawerOpen = true; $("#drBody").scrollTop = 0; $("#drClose").focus();
  return ++drawerToken;
}
function drawerSet(tok, html, title, sub) { if (tok !== drawerToken) return false; $("#drBody").innerHTML = html; if (title) $("#drTitle").textContent = title; if (sub !== undefined) $("#drSub").textContent = sub; wireAcc($("#drBody")); return true; }
function closeDrawer() { $("#drawer").hidden = $("#scrim").hidden = true; drawerOpen = false; drawerToken++; lastFocus && lastFocus.focus && lastFocus.focus(); }
function acc(title, body, open = false) { return `<div class="acc ${open ? "open" : ""}"><button aria-expanded="${open}">${title}${ic("chev")}</button><div><div>${body}</div></div></div>`; }
function wireAcc(root) { $$(".acc>button", root).forEach(b => b.onclick = () => { const a = b.parentElement; a.classList.toggle("open"); b.setAttribute("aria-expanded", a.classList.contains("open")); }); }
function table(cols, rows, opts = {}) {
  if (!rows.length) return empty(opts.emptyTitle || "Nothing to show", opts.emptyBody || "");
  return `<div class="tw" ${opts.style ? `style="${opts.style}"` : ""}><table><thead><tr>${cols.map(c => `<th class="${c.sort ? "s" : ""}" ${c.sort ? `data-sort="${c.key}"` : ""}>${c.label}</th>`).join("")}</tr></thead><tbody>${rows.map(r => `<tr class="${r._attr ? "click" : ""}" ${r._attr || ""}>${cols.map(c => `<td class="${c.cls || ""}">${c.render ? c.render(r) : esc(r[c.key])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
