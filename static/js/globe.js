"use strict";
/* Holographic globe: canvas-2D orthographic/perspective projection (no WebGL, no dependencies).
   Hosts with a GeoIP record sit on the surface at their real coordinates. Hosts without one (private/LAN or no GeoIP DB) orbit on rings and are
   labelled as unlocated - their position carries no geographic meaning. Arcs and packets come from real flows in the capture. */
class Globe {
  constructor(cv, host, onNode) {
    this.cv = cv; this.cx = cv.getContext("2d"); this.host = host; this.onNode = onNode;
    this.yaw = -0.6; this.pitch = 0.35; this.vy = REDUCED ? 0 : 0.12; this.drag = null; this.idleAt = 0; this.nodes = []; this.edges = []; this.byIp = {}; this.hover = null; this.visible = true; this.t0 = performance.now(); this.panels = [];
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(cv.parentElement);
    new IntersectionObserver(e => { this.visible = e[0].isIntersecting; if (this.visible) this.loop(); }).observe(cv);
    cv.addEventListener("pointerdown", e => { this.drag = {x: e.clientX, y: e.clientY, moved: 0}; cv.setPointerCapture(e.pointerId); });
    cv.addEventListener("pointermove", e => this.move(e));
    cv.addEventListener("pointerup", e => { const d = this.drag; this.drag = null; if (d && d.moved < 5 && this.hover) this.onNode && this.onNode(this.hover.ip); this.idleAt = performance.now() + 2500; });
    cv.addEventListener("pointerleave", () => { this.hover = null; });
    cv.setAttribute("role", "img"); cv.setAttribute("aria-label", "Interactive 3D network globe. Drag to rotate; click a node for details.");
    document.addEventListener("visibilitychange", () => { if (!document.hidden) this.loop(); });
    this.resize(); this.loop();
  }
  destroy() { this.dead = true; this.ro.disconnect(); this.panels.forEach(p => p.el.remove()); }
  resize() { const r = this.cv.parentElement.getBoundingClientRect(); this.dpr = Math.min(devicePixelRatio || 1, 2); this.W = r.width; this.H = r.height; this.cv.width = this.W * this.dpr; this.cv.height = this.H * this.dpr; this.cx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0); this.R = Math.min(this.W * 0.27, this.H * 0.30); if (REDUCED) this.draw(0); }
  setData(nodes, edges) {
    const loc = [], inner = [], outer = [];
    this.totalNodes = nodes.length; nodes = [...nodes].sort((a, b) => (b.score > 0) - (a.score > 0) || b.bytes - a.bytes).slice(0, 44);
    nodes = [...nodes].sort((a, b) => (b.score > 0) - (a.score > 0) || b.bytes - a.bytes).slice(0, 70);
    this.nodes = nodes.map(n => ({...n, alert: n.score > 0})); this.byIp = {};
    for (const n of this.nodes) { this.byIp[n.ip] = n; if (n.geo) loc.push(n); else if (["private", "loopback", "link-local"].includes(n.class)) inner.push(n); else outer.push(n); }
    for (const n of loc) { const la = n.geo.lat * Math.PI / 180, lo = n.geo.lon * Math.PI / 180; n.sph = [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)]; n.r = 1; n.kind = "geo"; }
    const ring = (arr, r, tilt, spin, kind) => arr.forEach((n, i) => { n.ring = {a: i / Math.max(arr.length, 1) * Math.PI * 2, r, tilt, spin}; n.kind = kind; });
    ring(inner, 1.3, 0.35, 0.10, "lan"); ring(outer, 1.55, -0.42, -0.07, "ring");
    this.hasInner = inner.length > 0; this.hasOuter = outer.length > 0; this.hasGeo = loc.length > 0;
    this.edges = edges.filter(e => this.byIp[e.s] && this.byIp[e.d]).sort((a, b) => b.bytes - a.bytes).slice(0, 60).map((e, i) => ({a: this.byIp[e.s], b: this.byIp[e.d], bytes: e.bytes, bad: (this.byIp[e.s].score > 0 || this.byIp[e.d].score > 0), off: (i * 0.37) % 1, n: e.bytes > 1e6 ? 3 : e.bytes > 1e4 ? 2 : 1}));
    this.buildPanels();
  }
  buildPanels() {
    this.panels.forEach(p => p.el.remove()); this.panels = [];
    const top = [...this.nodes].sort((a, b) => b.score - a.score || b.bytes - a.bytes).slice(0, 3);
    top.forEach(n => { const el = document.createElement("div"); el.className = "fpanel"; const g = n.geo; el.innerHTML = `<b>${esc(n.ip)}</b><small>${esc(n.name || (g ? [g.city, g.country].filter(Boolean).join(", ") : n.class + " · unlocated"))}</small><div class="row sb" style="margin-top:4px"><span>${fmtB(n.bytes)}</span>${n.score ? sev(n.level) : `<span class="tag">no findings</span>`}</div><div class="bar"><i style="width:${n.score}%"></i></div>`; el.onclick = () => this.onNode && this.onNode(n.ip); this.host.appendChild(el); this.panels.push({el, n}); });
  }
  move(e) {
    const r = this.cv.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    if (this.drag) { const dx = e.clientX - this.drag.x, dy = e.clientY - this.drag.y; this.drag.moved += Math.abs(dx) + Math.abs(dy); this.yaw += dx * 0.006; this.pitch = Math.max(-1.2, Math.min(1.2, this.pitch + dy * 0.004)); this.drag.x = e.clientX; this.drag.y = e.clientY; this.idleAt = performance.now() + 2500; }
    this.mx = mx; this.my = my;
  }
  rot(v, yaw) { const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(this.pitch), sp = Math.sin(this.pitch); let x = v[0] * cy + v[2] * sy, z = -v[0] * sy + v[2] * cy, y = v[1]; return [x, y * cp - z * sp, y * sp + z * cp]; }
  proj(v) { const f = 4 / (4 - v[2] * this.R / 300); return [this.W / 2 + v[0] * this.R * f, this.H / 2 - v[1] * this.R * f, v[2], f]; }
  pos(n, t) {
    if (n.kind === "geo") return this.rot(n.sph, this.yaw);
    const a = n.ring.a + t * n.ring.spin, c = Math.cos(a) * n.ring.r, s = Math.sin(a) * n.ring.r, tl = n.ring.tilt;
    return this.rot([c, s * Math.sin(tl), s * Math.cos(tl)], 0);
  }
  hidden(v) { return v[2] < 0 && v[0] * v[0] + v[1] * v[1] < 1; }
  loop() { if (this.looping || this.dead) return; this.looping = true; const step = now => { this.looping = false; if (this.dead || !this.visible || document.hidden) return; this.draw((now - this.t0) / 1000); if (!REDUCED) { this.looping = true; requestAnimationFrame(step); } }; requestAnimationFrame(step); }
  draw(t) {
    if (!(this.W > 50 && this.R > 10)) return;
    const c = this.cx, W = this.W, H = this.H, R = this.R, now = performance.now(); const dt = Math.min(0.05, t - (this.lt || t)); this.lt = t;
    if (!this.drag && now > this.idleAt && !(this.hover) && !REDUCED) this.yaw += this.vy * dt;
    c.clearRect(0, 0, W, H); const cx0 = W / 2, cy0 = H / 2;
    // atmosphere + sphere
    let g = c.createRadialGradient(cx0, cy0, R * 0.9, cx0, cy0, R * 1.35); g.addColorStop(0, "rgba(0,207,232,.28)"); g.addColorStop(1, "rgba(0,207,232,0)"); c.fillStyle = g; c.beginPath(); c.arc(cx0, cy0, R * 1.35, 0, 7); c.fill();
    g = c.createRadialGradient(cx0 - R * .35, cy0 - R * .4, R * .1, cx0, cy0, R); g.addColorStop(0, "rgba(255,255,255,.98)"); g.addColorStop(.6, "rgba(214,240,255,.85)"); g.addColorStop(1, "rgba(120,200,240,.55)"); c.fillStyle = g; c.beginPath(); c.arc(cx0, cy0, R, 0, 7); c.fill();
    c.strokeStyle = "rgba(0,207,232,.75)"; c.lineWidth = 1.6; c.stroke();
    // rings behind
    this.drawRings(t, false);
    // graticule
    c.lineWidth = 1;
    const line = (pts, back) => { let s = false; c.beginPath(); for (const p of pts) { const q = this.rot(p, this.yaw); if ((q[2] < 0) !== back) { s = false; continue; } const pr = this.proj(q); if (!s) { c.moveTo(pr[0], pr[1]); s = true; } else c.lineTo(pr[0], pr[1]); } c.stroke(); };
    for (const back of [true, false]) { c.strokeStyle = back ? "rgba(36,87,214,.10)" : "rgba(36,87,214,.30)";
      for (let lo = 0; lo < 360; lo += 30) { const pts = []; for (let la = -90; la <= 90; la += 6) { const a = la * Math.PI / 180, o = lo * Math.PI / 180; pts.push([Math.cos(a) * Math.sin(o), Math.sin(a), Math.cos(a) * Math.cos(o)]); } line(pts, back); }
      for (let la = -60; la <= 60; la += 30) { const pts = [], a = la * Math.PI / 180; for (let lo = 0; lo <= 360; lo += 6) { const o = lo * Math.PI / 180; pts.push([Math.cos(a) * Math.sin(o), Math.sin(a), Math.cos(a) * Math.cos(o)]); } line(pts, back); } }
    // positions
    for (const n of this.nodes) { n.v = this.pos(n, t); n.p = this.proj(n.v); }
    // edges
    for (const bad of [false, true]) {
      c.strokeStyle = bad ? "rgba(255,120,60,.75)" : "rgba(0,170,215,.38)"; c.lineWidth = bad ? 1.6 : 1.1; c.beginPath();
      for (const e of this.edges) { if (e.bad !== bad) continue; e.pts = this.arc(e); let s = false; for (const q of e.pts) { if (q.h) { s = false; continue; } if (!s) { c.moveTo(q.x, q.y); s = true; } else c.lineTo(q.x, q.y); } }
      c.stroke();
    }
    // packets with trails
    if (!REDUCED) for (const e of this.edges) { if (!e.pts) continue; for (let k = 0; k < e.n; k++) { const ph = (t * 0.22 + e.off + k / e.n) % 1; for (let tr = 0; tr < 5; tr++) { const idx = Math.floor((ph - tr * 0.018 + 1) % 1 * (e.pts.length - 1)), q = e.pts[idx]; if (!q || q.h) continue; c.fillStyle = (e.bad ? "255,110,50," : "0,190,225,") ; c.fillStyle = `rgba(${e.bad ? "255,110,50" : "0,190,225"},${(1 - tr / 5) * 0.9})`; c.beginPath(); c.arc(q.x, q.y, 2.6 - tr * 0.35, 0, 7); c.fill(); } } }
    this.drawRings(t, true);
    // nodes
    let best = null, bd = 14;
    for (const n of this.nodes) {
      const hid = this.hidden(n.v) || (n.kind === "geo" && n.v[2] < 0); n.hid = hid; const col = n.score >= 60 ? "#E94B64" : n.score > 0 ? "#FF9D42" : n.kind === "geo" ? "#2457D6" : "#00B5D0"; const sz = 3.5 + Math.min(5, Math.log10(n.bytes + 10) * .7);
      c.globalAlpha = hid ? .12 : 1; c.fillStyle = col; c.beginPath(); c.arc(n.p[0], n.p[1], sz, 0, 7); c.fill();
      if (!hid) { c.strokeStyle = "#fff"; c.lineWidth = 1.5; c.stroke(); if (n.score > 0 && !REDUCED) { const pr = (t * 1.2 + n.p[0]) % 1; c.strokeStyle = col; c.globalAlpha = 1 - pr; c.lineWidth = 1.5; c.beginPath(); c.arc(n.p[0], n.p[1], sz + pr * 16, 0, 7); c.stroke(); } }
      c.globalAlpha = 1;
      if (!hid && this.mx !== undefined) { const d = Math.hypot(this.mx - n.p[0], this.my - n.p[1]); if (d < bd) { bd = d; best = n; } }
    }
    this.hover = best; this.cv.style.cursor = best ? "pointer" : (this.drag ? "grabbing" : "grab");
    if (best) { const l = best.ip + (best.name ? " · " + best.name : ""); c.font = "600 12px Manrope,sans-serif"; const w = c.measureText(l).width + 16; let x = Math.min(W - w - 8, best.p[0] + 12), y = best.p[1] - 30; c.fillStyle = "rgba(23,43,77,.92)"; c.beginPath(); c.roundRect(x, y, w, 24, 8); c.fill(); c.fillStyle = "#fff"; c.fillText(l, x + 8, y + 16); }
    this.panels.forEach((p, i) => { const n = p.n, show = !n.hid && n.p; p.el.classList.toggle("on", !!show); if (!show) return;
      const left = i % 2 === 0, x = left ? 16 : W - 228, y = [H * 0.2, H * 0.3, H * 0.6][i] || H * 0.4; p.el.style.transform = `translate(${x.toFixed(1)}px,${y.toFixed(1)}px)`;
      c.strokeStyle = "rgba(36,87,214,.45)"; c.lineWidth = 1; c.setLineDash([3, 4]); c.beginPath(); c.moveTo(left ? x + 212 : x, y + 34); c.lineTo(n.p[0], n.p[1]); c.stroke(); c.setLineDash([]); });
  }
  drawRings(t, front) {
    const c = this.cx; const defs = []; if (this.hasInner) defs.push([1.3, .35, "rgba(0,207,232,"]); if (this.hasOuter) defs.push([1.55, -.42, "rgba(36,87,214,"]);
    for (const [r, tl, col] of defs) { c.strokeStyle = col + (front ? ".35)" : ".12)"); c.lineWidth = 1.2; c.setLineDash([2, 5]); c.beginPath(); let s = false; for (let a = 0; a <= 6.4; a += .1) { const v = this.rot([Math.cos(a) * r, Math.sin(a) * r * Math.sin(tl), Math.sin(a) * r * Math.cos(tl)], 0); if ((v[2] >= 0) !== front) { s = false; continue; } const p = this.proj(v); if (!s) { c.moveTo(p[0], p[1]); s = true; } else c.lineTo(p[0], p[1]); } c.stroke(); c.setLineDash([]); }
  }
  arc(e) {
    const A = e.a.v, B = e.b.v, la = Math.hypot(...A), lb = Math.hypot(...B), a = A.map(x => x / la), b = B.map(x => x / lb), d = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2])), om = Math.acos(d) || 1e-4, out = [], N = 26, sn = Math.sin(om);
    for (let i = 0; i <= N; i++) { const t = i / N, k1 = Math.sin((1 - t) * om) / sn, k2 = Math.sin(t * om) / sn; let v = [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2]; const L = Math.hypot(...v) || 1, rr = la + (lb - la) * t + Math.sin(Math.PI * t) * (0.06 + om * 0.14); v = v.map(x => x / L * rr); const p = this.proj(v); out.push({x: p[0], y: p[1], h: this.hidden(v)}); }
    return out;
  }
}

class Radar {
  constructor(cv, onPick) { this.cv = cv; this.cx = cv.getContext("2d"); this.onPick = onPick; this.blips = []; this.vis = true; this.dead = false;
    new ResizeObserver(() => this.resize()).observe(cv.parentElement); new IntersectionObserver(e => { this.vis = e[0].isIntersecting; if (this.vis) this.loop(); }).observe(cv);
    cv.onclick = e => { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top; const b = this.blips.find(b => Math.hypot(b.x - x, b.y - y) < 9); if (b) onPick(b.ip); };
    cv.setAttribute("role", "img"); cv.setAttribute("aria-label", "Threat radar. Hosts closer to the centre have a higher threat score."); this.resize(); this.loop(); }
  resize() { const r = this.cv.parentElement.getBoundingClientRect(); this.S = r.width; this.dpr = Math.min(devicePixelRatio || 1, 2); this.cv.width = this.cv.height = this.S * this.dpr; this.cx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0); if (REDUCED) this.draw(0); }
  setData(hosts) {
    const h = s => { let x = 2166136261; for (const c of s) { x ^= c.charCodeAt(0); x = Math.imul(x, 16777619); } return (x >>> 0) / 4294967295; };
    this.blips = [...hosts].sort((a, b) => b.score - a.score || b.bytes - a.bytes).slice(0, 36).map(n => ({ip: n.ip, score: n.score, ang: h(n.ip) * Math.PI * 2, rad: n.score > 0 ? 0.22 + 0.7 * (1 - n.score / 100) : 0.72 + 0.22 * h(n.ip + "r"), x: 0, y: 0}));
  }
  loop() { if (this.looping || this.dead) return; this.looping = true; const t0 = performance.now(); const step = now => { this.looping = false; if (this.dead || !this.vis || document.hidden) return; this.draw((now - t0) / 1000); if (!REDUCED) { this.looping = true; requestAnimationFrame(step); } }; requestAnimationFrame(step); }
  draw(t) {
    if (!(this.S > 40)) return;
    const c = this.cx, S = this.S, m = S / 2, R = m - 8, sw = (t * 1.1) % (Math.PI * 2); c.clearRect(0, 0, S, S);
    let g = c.createRadialGradient(m, m, 0, m, m, R); g.addColorStop(0, "rgba(255,255,255,.95)"); g.addColorStop(1, "rgba(0,207,232,.12)"); c.fillStyle = g; c.beginPath(); c.arc(m, m, R, 0, 7); c.fill();
    c.strokeStyle = "rgba(36,87,214,.22)"; c.lineWidth = 1; for (let i = 1; i <= 4; i++) { c.beginPath(); c.arc(m, m, R * i / 4, 0, 7); c.stroke(); }
    c.beginPath(); c.moveTo(m - R, m); c.lineTo(m + R, m); c.moveTo(m, m - R); c.lineTo(m, m + R); c.stroke();
    if (c.createConicGradient) { g = c.createConicGradient(sw - 1.1, m, m); g.addColorStop(0, "rgba(0,207,232,0)"); g.addColorStop(.17, "rgba(0,207,232,.38)"); g.addColorStop(.1751, "rgba(0,207,232,0)"); g.addColorStop(1, "rgba(0,207,232,0)"); c.fillStyle = g; c.beginPath(); c.arc(m, m, R, 0, 7); c.fill(); }
    c.strokeStyle = "rgba(0,185,215,.9)"; c.lineWidth = 2; c.beginPath(); c.moveTo(m, m); c.lineTo(m + Math.cos(sw) * R, m + Math.sin(sw) * R); c.stroke();
    for (const b of this.blips) { b.x = m + Math.cos(b.ang) * b.rad * R; b.y = m + Math.sin(b.ang) * b.rad * R; const since = ((sw - b.ang) % 6.2832 + 6.2832) % 6.2832, glow = REDUCED ? .6 : Math.max(0, 1 - since / 3); const col = b.score >= 60 ? "233,75,100" : b.score > 0 ? "255,157,66" : "36,87,214";
      c.fillStyle = `rgba(${col},${.4 + glow * .6})`; c.beginPath(); c.arc(b.x, b.y, 3.6 + glow * 2.5, 0, 7); c.fill(); if (glow > .4) { c.strokeStyle = `rgba(${col},${glow * .5})`; c.beginPath(); c.arc(b.x, b.y, 7 + (1 - glow) * 10, 0, 7); c.stroke(); } }
    c.strokeStyle = "rgba(0,207,232,.7)"; c.lineWidth = 1.5; c.beginPath(); c.arc(m, m, R, 0, 7); c.stroke();
  }
}
