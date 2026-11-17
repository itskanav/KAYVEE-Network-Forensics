"use strict";
function setupCanvas(cv) { const r = cv.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2); cv.width = Math.max(1, r.width * d); cv.height = Math.max(1, r.height * d); const c = cv.getContext("2d"); c.setTransform(d, 0, 0, d, 0, 0); return [c, r.width, r.height]; }

// Multi-series line/area chart with hover tooltip.
function areaChart(box, o) {
  box.innerHTML = `<canvas style="width:100%;height:100%;display:block" role="img" aria-label="${esc(o.label || "Traffic chart")}"></canvas><div class="tip" style="position:absolute;pointer-events:none;background:rgba(23,43,77,.92);color:#fff;border-radius:10px;padding:6px 10px;font-size:12px;display:none;white-space:nowrap;z-index:2"></div>`;
  box.style.position = "relative"; const cv = $("canvas", box), tip = $(".tip", box); let hov = -1, prog = REDUCED ? 1 : 0;
  const n = Math.max(...o.series.map(s => s.data.length)), max = Math.max(1, ...o.series.flatMap(s => s.data)) * 1.1, P = {l: 52, r: 10, t: 10, b: 24};
  function draw() {
    const [c, W, H] = setupCanvas(cv); c.clearRect(0, 0, W, H); const iw = W - P.l - P.r, ih = H - P.t - P.b, X = i => P.l + (n <= 1 ? 0 : i / (n - 1)) * iw, Y = v => P.t + ih - v / max * ih * prog;
    c.font = "11px Manrope,sans-serif"; c.fillStyle = "#566685"; c.strokeStyle = "rgba(36,87,214,.10)"; c.lineWidth = 1;
    for (let i = 0; i <= 4; i++) { const y = P.t + ih * i / 4; c.beginPath(); c.moveTo(P.l, y); c.lineTo(W - P.r, y); c.stroke(); c.textAlign = "right"; c.fillText(o.yfmt(max * (4 - i) / 4), P.l - 6, y + 4); }
    c.textAlign = "center"; for (let i = 0; i <= 4; i++) { const idx = Math.round((n - 1) * i / 4); c.fillText(o.xfmt(idx), Math.min(W - 30, Math.max(P.l + 20, X(idx))), H - 6); }
    for (const s of o.series) { const g = c.createLinearGradient(0, P.t, 0, P.t + ih); g.addColorStop(0, s.color + "55"); g.addColorStop(1, s.color + "00"); c.beginPath(); s.data.forEach((v, i) => i ? c.lineTo(X(i), Y(v)) : c.moveTo(X(i), Y(v))); c.strokeStyle = s.color; c.lineWidth = 2; c.stroke(); c.lineTo(X(s.data.length - 1), P.t + ih); c.lineTo(X(0), P.t + ih); c.closePath(); c.fillStyle = g; c.fill(); }
    if (hov >= 0) { c.strokeStyle = "rgba(23,43,77,.4)"; c.beginPath(); c.moveTo(X(hov), P.t); c.lineTo(X(hov), P.t + ih); c.stroke(); for (const s of o.series) { c.fillStyle = s.color; c.beginPath(); c.arc(X(hov), Y(s.data[hov] || 0), 4, 0, 7); c.fill(); } }
  }
  cv.onpointermove = e => { const r = cv.getBoundingClientRect(), i = Math.round((e.clientX - r.left - P.l) / (r.width - P.l - P.r) * (n - 1)); hov = Math.max(0, Math.min(n - 1, i)); draw(); tip.style.display = "block"; tip.innerHTML = `<b>${esc(o.xfmt(hov, true))}</b><br>` + o.series.map(s => `<span style="color:${s.color}">●</span> ${esc(s.name)}: ${esc(o.yfmt(s.data[hov] || 0))}`).join("<br>"); tip.style.left = Math.min(r.width - tip.offsetWidth - 4, e.clientX - r.left + 12) + "px"; tip.style.top = "8px"; };
  cv.onpointerleave = () => { hov = -1; tip.style.display = "none"; draw(); };
  const ro = new ResizeObserver(draw); ro.observe(box); draw();
  if (!REDUCED) { const t0 = performance.now(); (function a(t) { prog = Math.min(1, (t - t0) / 800); prog = 1 - Math.pow(1 - prog, 3); draw(); if (prog < 1 && box.isConnected) requestAnimationFrame(a); })(t0); }
  return {redraw: draw};
}

// Outgoing (up) / incoming (down) mirrored waveform. data = real per-bin byte counts.
function waveform(cv, out, inn, anim = true) {
  const n = out.length, mx = Math.max(1, ...out, ...inn); let ph = 0, dead = false;
  function draw() {
    const [c, W, H] = setupCanvas(cv), m = H / 2; c.clearRect(0, 0, W, H); const X = i => n <= 1 ? 0 : i / (n - 1) * W;
    c.strokeStyle = "rgba(36,87,214,.18)"; c.beginPath(); c.moveTo(0, m); c.lineTo(W, m); c.stroke();
    for (const [arr, dir, col] of [[out, -1, "#00CFE8"], [inn, 1, "#2457D6"]]) { const g = c.createLinearGradient(0, m, 0, m + dir * m); g.addColorStop(0, col + "AA"); g.addColorStop(1, col + "10"); c.beginPath(); c.moveTo(0, m); arr.forEach((v, i) => { const x = X(i), y = m + dir * (v / mx) * (m - 4); i ? c.lineTo(x, y) : c.lineTo(x, y); }); c.lineTo(W, m); c.closePath(); c.fillStyle = g; c.fill(); c.strokeStyle = col; c.lineWidth = 1.5; c.stroke(); }
    if (anim && !REDUCED) { const x = (ph % 1) * W, g = c.createLinearGradient(x - 60, 0, x + 60, 0); g.addColorStop(0, "rgba(255,255,255,0)"); g.addColorStop(.5, "rgba(255,255,255,.65)"); g.addColorStop(1, "rgba(255,255,255,0)"); c.fillStyle = g; c.fillRect(x - 60, 0, 120, H); }
    c.font = "11px Manrope,sans-serif"; c.fillStyle = "#566685"; c.fillText("outbound ▲", 6, 12); c.fillText("inbound ▼", 6, H - 5);
  }
  draw(); if (anim && !REDUCED) (function a() { if (dead || !cv.isConnected) return; ph += .004; draw(); requestAnimationFrame(a); })();
  new ResizeObserver(draw).observe(cv.parentElement); return {stop: () => dead = true, draw};
}

const PROTO_COL = ["#2457D6", "#00CFE8", "#FF9D42", "#18B887", "#E94B64", "#8F6BE8", "#E8B029", "#5BA7FF", "#7ED3C1", "#C77DA3"];
function donut(box, data, onClick) {
  const ent = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 9), tot = ent.reduce((s, e) => s + e[1], 0);
  if (!tot) { box.innerHTML = empty("No protocol data", ""); return; }
  const R = 52, C = 2 * Math.PI * R; let off = 0;
  const arcs = ent.map(([k, v], i) => { const len = v / tot * C, a = `<circle class="seg" data-k="${esc(k)}" r="${R}" cx="70" cy="70" fill="none" stroke="${PROTO_COL[i % 10]}" stroke-width="18" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" style="cursor:pointer;transition:stroke-width .2s" tabindex="0" role="button" aria-label="${esc(k)} ${v} packets"><title>${esc(k)}: ${fmtN(v)}</title></circle>`; off += len; return a; }).join("");
  box.innerHTML = `<div class="row" style="gap:18px;flex-wrap:nowrap"><svg viewBox="0 0 140 140" style="width:150px;height:150px;transform:rotate(-90deg);flex:none">${arcs}</svg><div style="min-width:0;flex:1">${ent.map(([k, v], i) => `<div class="row" style="gap:8px;margin:3px 0;cursor:pointer" data-k="${esc(k)}"><i style="width:10px;height:10px;border-radius:3px;background:${PROTO_COL[i % 10]}"></i><span style="flex:1;overflow:hidden;text-overflow:ellipsis">${esc(k)}</span><b>${(v / tot * 100).toFixed(1)}%</b></div>`).join("")}</div></div>`;
  $$("[data-k]", box).forEach(el => { el.onclick = () => onClick && onClick(el.dataset.k); el.onkeydown = e => e.key === "Enter" && onClick && onClick(el.dataset.k); el.onmouseenter = () => { const s = $(`circle[data-k="${CSS.escape(el.dataset.k)}"]`, box); s && s.setAttribute("stroke-width", 24); }; el.onmouseleave = () => $$("circle", box).forEach(s => s.setAttribute("stroke-width", 18)); });
}

function hbars(items, fmt = fmtN) {
  if (!items.length) return empty("No data", "");
  const mx = Math.max(1, ...items.map(i => i.value));
  const html = `<div class="bars">${items.map(i => `<div class="b ${i.attr ? "click" : ""}" ${i.attr || ""}><span title="${esc(i.label)}">${i.html || esc(i.label)}</span><div class="t"><i data-w="${(i.value / mx * 100).toFixed(1)}" ${i.color ? `style="background:${i.color}"` : ""}></i></div><span>${fmt(i.value)}</span></div>`).join("")}</div>`;
  return html;
}
function animateBars(root, instant) { if (instant) { $$(".bars i[data-w]", root).forEach(i => { i.style.transition = "none"; i.style.width = i.dataset.w + "%"; }); return; } requestAnimationFrame(() => $$(".bars i[data-w]", root).forEach(i => i.style.width = i.dataset.w + "%")); }

// Forensic event timeline: lanes per category, dots coloured by severity. onClick(event)
function timelineSVG(box, events, t0, t1, onClick) {
  const cats = [...new Set(events.map(e => e.kind))]; const W = Math.max(640, box.clientWidth), lane = 38, H = cats.length * lane + 34, L = 120, span = Math.max(1e-3, t1 - t0);
  const X = t => L + (t - t0) / span * (W - L - 24);
  let s = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:${H}px;display:block" role="img" aria-label="Attack timeline">`;
  cats.forEach((c, i) => { const y = 14 + i * lane; s += `<line x1="${L}" x2="${W - 14}" y1="${y + 12}" y2="${y + 12}" stroke="rgba(36,87,214,.12)"/><text x="6" y="${y + 16}" font-size="12" font-weight="700" fill="#566685">${esc(c.replace(/_/g, " ").toLowerCase())}</text>`; });
  for (let i = 0; i <= 5; i++) { const t = t0 + span * i / 5, x = X(t); s += `<line x1="${x}" x2="${x}" y1="6" y2="${H - 22}" stroke="rgba(36,87,214,.06)"/><text x="${x}" y="${H - 6}" font-size="11" fill="#566685" text-anchor="middle">${new Date(t * 1000).toISOString().slice(11, 19)}</text>`; }
  events.forEach(e => { const y = 14 + cats.indexOf(e.kind) * lane + 12, x = X(e.ts), x2 = e.end ? Math.max(x + 6, X(e.end)) : x, col = SEV_COLOR[e.severity] || "#8DA2C0";
    if (x2 - x > 8) s += `<rect x="${x}" y="${y - 5}" width="${x2 - x}" height="10" rx="5" fill="${col}" opacity=".28"/>`;
    s += `<circle class="ev" data-i="${e.idx}" cx="${x}" cy="${y}" r="7" fill="${col}" stroke="#fff" stroke-width="2" tabindex="0" role="button" aria-label="${esc(e.title)}" style="cursor:pointer"><title>${esc(fmtT(e.ts))} — ${esc(e.title)}</title></circle>`; });
  box.innerHTML = s + "</svg>";
  $$(".ev", box).forEach(c => { const f = () => onClick(events.find(e => e.idx == c.dataset.i)); c.onclick = f; c.onkeydown = e => e.key === "Enter" && f(); c.onmouseenter = () => c.setAttribute("r", 10); c.onmouseleave = () => c.setAttribute("r", 7); });
}

// Interactive force-directed network topology
class Topology {
  constructor(cv, graph, onNode) {
    this.cv = cv; this.onNode = onNode; this.k = 1; this.ox = 0; this.oy = 0; this.sel = null;
    const N = graph.nodes.slice(0, 140); this.nodes = N.map((n, i) => ({...n, x: Math.cos(i) * 150 * Math.random(), y: Math.sin(i) * 150 * Math.random(), vx: 0, vy: 0}));
    const by = Object.fromEntries(this.nodes.map(n => [n.ip, n])); this.edges = graph.edges.filter(e => by[e.s] && by[e.d]).map(e => ({...e, a: by[e.s], b: by[e.d]}));
    this.energy = 1; this.drag = null;
    cv.onpointerdown = e => { const p = this.world(e); const n = this.pick(p); this.drag = {n, x: e.clientX, y: e.clientY, moved: 0}; cv.setPointerCapture(e.pointerId); };
    cv.onpointermove = e => { const p = this.world(e); if (this.drag) { const d = this.drag; d.moved += Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y); if (d.n) { d.n.x = p.x; d.n.y = p.y; d.n.vx = d.n.vy = 0; this.energy = Math.max(this.energy, .3); } else { this.ox += e.clientX - d.x; this.oy += e.clientY - d.y; } d.x = e.clientX; d.y = e.clientY; } else { this.hov = this.pick(p); cv.style.cursor = this.hov ? "pointer" : "grab"; } if (REDUCED) this.draw(); };
    cv.onpointerup = () => { const d = this.drag; this.drag = null; if (d && d.moved < 5 && d.n) { this.sel = d.n; onNode(d.n.ip); } };
    cv.onwheel = e => { e.preventDefault(); const f = e.deltaY < 0 ? 1.12 : .89, r = cv.getBoundingClientRect(), mx = e.clientX - r.left - r.width / 2, my = e.clientY - r.top - r.height / 2; this.ox = mx - (mx - this.ox) * f; this.oy = my - (my - this.oy) * f; this.k = Math.max(.3, Math.min(4, this.k * f)); if (REDUCED) this.draw(); };
    this.ro = new ResizeObserver(() => { this.sz = setupCanvas(cv); if (REDUCED) this.draw(); }); this.ro.observe(cv.parentElement); this.sz = setupCanvas(cv);
    if (REDUCED) { for (let i = 0; i < 300; i++) this.step(); this.draw(); } else this.loop();
  }
  world(e) { const r = this.cv.getBoundingClientRect(); return {x: (e.clientX - r.left - r.width / 2 - this.ox) / this.k, y: (e.clientY - r.top - r.height / 2 - this.oy) / this.k}; }
  pick(p) { let b = null, bd = 99; for (const n of this.nodes) { const d = Math.hypot(n.x - p.x, n.y - p.y) * this.k; if (d < Math.max(11, this.rad(n) + 4) && d < bd) { b = n; bd = d; } } return b; }
  rad(n) { return 5 + Math.min(11, Math.log10(n.bytes + 10) * 1.5); }
  step() {
    const N = this.nodes, a = this.energy; for (let i = 0; i < N.length; i++) for (let j = i + 1; j < N.length; j++) { let dx = N[i].x - N[j].x, dy = N[i].y - N[j].y, d2 = dx * dx + dy * dy + 40; const f = 5200 / d2, d = Math.sqrt(d2); dx /= d; dy /= d; N[i].vx += dx * f * a; N[i].vy += dy * f * a; N[j].vx -= dx * f * a; N[j].vy -= dy * f * a; }
    for (const e of this.edges) { const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.hypot(dx, dy) || 1, f = (d - 90) * 0.02 * a; e.a.vx += dx / d * f; e.a.vy += dy / d * f; e.b.vx -= dx / d * f; e.b.vy -= dy / d * f; }
    for (const n of N) { n.vx += -n.x * .004 * a; n.vy += -n.y * .004 * a; if (this.drag && this.drag.n === n) continue; n.x += n.vx * .5; n.y += n.vy * .5; n.vx *= .6; n.vy *= .6; }
    this.energy = Math.max(.02, this.energy * .992);
  }
  loop() { const f = () => { if (!this.cv.isConnected) { this.ro.disconnect(); return; } this.step(); this.draw(); this.raf = requestAnimationFrame(f); }; f(); }
  draw() {
    const [c, W, H] = this.sz; if (!c) return; c.setTransform(this.cv.width / W, 0, 0, this.cv.height / H, 0, 0); c.clearRect(0, 0, W, H); c.save(); c.translate(W / 2 + this.ox, H / 2 + this.oy); c.scale(this.k, this.k);
    const t = performance.now() / 1000, mx = Math.max(1, ...this.edges.map(e => e.bytes));
    for (const e of this.edges) { const bad = e.a.score > 0 || e.b.score > 0, hl = this.sel && (e.a === this.sel || e.b === this.sel); c.strokeStyle = bad ? "rgba(255,120,60,.6)" : hl ? "rgba(36,87,214,.7)" : "rgba(0,160,210,.28)"; c.lineWidth = (0.6 + 2.6 * Math.sqrt(e.bytes / mx)) / Math.sqrt(this.k); c.beginPath(); c.moveTo(e.a.x, e.a.y); c.lineTo(e.b.x, e.b.y); c.stroke();
      if (!REDUCED && (hl || bad || this.nodes.length < 40)) { const p = (t * .35 + e.bytes % 7 / 7) % 1; c.fillStyle = bad ? "#FF7A3C" : "#00BFE0"; c.beginPath(); c.arc(e.a.x + (e.b.x - e.a.x) * p, e.a.y + (e.b.y - e.a.y) * p, 2.4 / Math.sqrt(this.k), 0, 7); c.fill(); } }
    for (const n of this.nodes) { const col = n.score >= 60 ? "#E94B64" : n.score > 0 ? "#FF9D42" : n.class === "public" ? "#2457D6" : "#00B5D0", r = this.rad(n); if (n.score > 0 && !REDUCED) { const p = (((t + n.x) % 1.2) + 1.2) % 1.2 / 1.2; c.strokeStyle = col; c.globalAlpha = 1 - p; c.beginPath(); c.arc(n.x, n.y, r + p * 14, 0, 7); c.stroke(); c.globalAlpha = 1; }
      c.fillStyle = col; c.beginPath(); c.arc(n.x, n.y, r, 0, 7); c.fill(); c.strokeStyle = n === this.sel ? "#172B4D" : "#fff"; c.lineWidth = n === this.sel ? 3 : 2; c.stroke();
      if (this.k > .7 || n === this.hov || n === this.sel || n.score > 0) { c.fillStyle = "#172B4D"; c.font = `600 ${11 / Math.sqrt(this.k)}px Manrope,sans-serif`; c.textAlign = "center"; c.fillText(n.name || n.ip, n.x, n.y + r + 13 / Math.sqrt(this.k)); } }
    c.restore();
  }
}
