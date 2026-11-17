"use strict";
// Particle + connection-line background (paused when tab hidden)
(function () {
  const cv = $("#bg"), cx = cv.getContext("2d"); let W, H, P = [], run = true, dpr = Math.min(devicePixelRatio || 1, 1.5);
  function size() { W = innerWidth; H = innerHeight; cv.width = W * dpr; cv.height = H * dpr; cx.setTransform(dpr, 0, 0, dpr, 0, 0); const n = Math.round(Math.min(70, W * H / 26000)); P = Array.from({length: n}, () => ({x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25, r: 1 + Math.random() * 1.6})); draw(); }
  function draw() {
    cx.clearRect(0, 0, W, H);
    for (const p of P) { if (!REDUCED) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1; } }
    for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) { const dx = P[i].x - P[j].x, dy = P[i].y - P[j].y, d = dx * dx + dy * dy; if (d < 16000) { cx.strokeStyle = `rgba(36,120,214,${.13 * (1 - d / 16000)})`; cx.lineWidth = 1; cx.beginPath(); cx.moveTo(P[i].x, P[i].y); cx.lineTo(P[j].x, P[j].y); cx.stroke(); } }
    for (const p of P) { cx.fillStyle = "rgba(0,185,215,.45)"; cx.beginPath(); cx.arc(p.x, p.y, p.r, 0, 6.283); cx.fill(); }
  }
  function loop() { if (run && !REDUCED) { draw(); requestAnimationFrame(loop); } }
  addEventListener("resize", size); document.addEventListener("visibilitychange", () => { run = !document.hidden; if (run) loop(); });
  size(); loop();
})();

// 3D tilt on cards + magnetic buttons (event delegation, rAF throttled)
(function () {
  if (REDUCED) return;
  let raf = 0, cur = null, ev = null;
  document.addEventListener("pointermove", e => { ev = e; if (!raf) raf = requestAnimationFrame(() => { raf = 0; const e = ev; const card = e.target.closest && e.target.closest(".tilt");
    if (cur && cur !== card) { cur.style.transform = ""; cur = null; }
    if (card && !card.classList.contains("no-tilt")) { const r = card.getBoundingClientRect(), x = (e.clientX - r.left) / r.width - .5, y = (e.clientY - r.top) / r.height - .5; card.style.transform = `perspective(900px) rotateX(${(-y * 5).toFixed(2)}deg) rotateY(${(x * 6).toFixed(2)}deg) translateZ(0)`; cur = card; }
    const m = e.target.closest && e.target.closest(".btn,.icon-btn");
    $$(".mag-on").forEach(b => { if (b !== m) { b.style.transform = ""; b.classList.remove("mag-on"); } });
    if (m) { const r = m.getBoundingClientRect(), dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height / 2); m.style.transform = `translate(${(dx * .12).toFixed(1)}px,${(dy * .18).toFixed(1)}px)`; m.classList.add("mag-on"); } }); });
  document.addEventListener("pointerleave", () => { if (cur) cur.style.transform = ""; $$(".mag-on").forEach(b => b.style.transform = ""); }, true);
})();

function countUp(el, target, fmt = fmtN, ms = 900) {
  if (!el) return; target = +target || 0;
  if (REDUCED || target === 0) { el.textContent = fmt(target); return; }
  const t0 = performance.now(), from = +el.dataset.v || 0; el.dataset.v = target;
  (function step(t) { const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3); el.textContent = fmt(from + (target - from) * e); if (k < 1 && el.isConnected) requestAnimationFrame(step); else el.textContent = fmt(target); })(t0);
}

// cinematic intro (once per session)
function playIntro(done) {
  const el = $("#intro"); let ended = false;
  const end = () => { if (ended) return; ended = true; el.classList.add("out"); setTimeout(() => { el.remove(); }, 800); done(); };
  if (REDUCED || sessionStorage.getItem("kv-intro")) { el.remove(); done(); return; }
  try { sessionStorage.setItem("kv-intro", "1"); } catch {}
  $("#introSkip").onclick = end; setTimeout(end, 3100);
}
