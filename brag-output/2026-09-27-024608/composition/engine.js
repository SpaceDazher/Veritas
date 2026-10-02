/* engine.js — deterministic promo-video renderer (repovideo skill).
 *
 * The page loads fonts.js, then spec.js (window.__SPEC, optional window.__VOICE),
 * then this file. Nothing is read from disk or the network, and no wall clock is
 * consulted: frame i always draws the same pixels, so a re-render is byte-stable.
 *
 * Public surface consumed by scripts/render.mjs:
 *   __ready, __error, __NDRAW, __fps, __size, __duration
 *   __frame(i) -> data:image/png      __wav() -> base64 WAV
 *   __poster() -> {index, url}        __contact(cols, rows) -> data URL
 *   __strip(start, count) -> data URL __scenes() -> [{kind,start,end,text}]
 */
(() => {
  'use strict';

  const spec = window.__SPEC;
  if (!spec) { window.__error = 'window.__SPEC is not defined (spec.js missing)'; return; }

  /* ------------------------------------------------------------------ sizes */
  const FORMATS = {landscape: [1920, 1080], vertical: [1080, 1920], square: [1080, 1080], wide: [2560, 1080]};
  const [W, H] = FORMATS[spec.format] || FORMATS.landscape;
  const FPS = spec.fps || 30;
  const U = Math.min(W, H) / 1080;                 // type unit
  const isTall = H > W * 1.2;

  /* ---------------------------------------------------------------- palette */
  const PALETTES = {
    aurora: {bg: ['#060a16', '#0c1a38'], fg: '#f3f7ff', muted: '#93a6cc', accent: '#4ade9b', accent2: '#5aa8ff', panel: '#0d1c33'},
    dusk:   {bg: ['#150c1e', '#2c1339'], fg: '#fff6ee', muted: '#c2a6c8', accent: '#ff7a59', accent2: '#ffd166', panel: '#20102c'},
    neon:   {bg: ['#08060f', '#170a20'], fg: '#fdf3ff', muted: '#a79ec0', accent: '#ff3d81', accent2: '#22e0ff', panel: '#150a1c'},
    ember:  {bg: ['#110806', '#2b1008'], fg: '#fff6f0', muted: '#cfa595', accent: '#ff5a1f', accent2: '#ffc14d', panel: '#1f0d08'},
    mono:   {bg: ['#0a0a0b', '#17171a'], fg: '#fafafa', muted: '#a1a1aa', accent: '#ffffff', accent2: '#c9c9d1', panel: '#131316'},
    solar:  {bg: ['#0c0e06', '#1f2a0b'], fg: '#f8ffe9', muted: '#b6c79a', accent: '#c9f24e', accent2: '#5ad68c', panel: '#161d0a'},
    ice:    {bg: ['#060f18', '#0d2334'], fg: '#eefaff', muted: '#9dbdd4', accent: '#6ee7ff', accent2: '#a78bfa', panel: '#0a1c2b'},
    paper:  {bg: ['#f4efe6', '#e7dfd0'], fg: '#1b1714', muted: '#6d635a', accent: '#d6491f', accent2: '#2f6f5e', panel: '#fffdf8'},
  };
  const P = Object.assign({}, PALETTES[spec.palette] || PALETTES.aurora, spec.colors || {});
  P.bg = (spec.colors && spec.colors.bg) ? (Array.isArray(spec.colors.bg) ? spec.colors.bg : [spec.colors.bg, spec.colors.bg]) : P.bg;

  // Terminal text always sits on the dark ink panel above, so these are fixed
  // terminal colours on every palette — slide-palette text was unreadable there.
  const CODE_COLORS = {
    plain: '#e6e6ea', dim: '#8b90a0', keyword: '#ff86c8', string: '#8fe3a8', comment: '#7f8aa3',
    number: '#f2b880', accent: '#ff9d5c', fn: '#8ab4ff', type: '#ffd479',
  };

  /* ------------------------------------------------------------------ math */
  const clamp = (v, a = 0, b = 1) => (v < a ? a : v > b ? b : v);
  const seg = (t, a, b) => {
    if (b == null) { console.warn('engine: seg() without an end time — treating it as a 0.2s window'); return clamp((t - a) / 0.2); }
    return clamp((t - a) / (b - a));
  };
  const lerp = (a, b, p) => a + (b - a) * p;
  const E = {
    linear: p => p,
    inQuad: p => p * p,
    outQuad: p => 1 - (1 - p) * (1 - p),
    outCubic: p => 1 - Math.pow(1 - p, 3),
    inOutCubic: p => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2),
    outExpo: p => (p >= 1 ? 1 : 1 - Math.pow(2, -10 * p)),
    inExpo: p => (p <= 0 ? 0 : Math.pow(2, 10 * p - 10)),
    outQuint: p => 1 - Math.pow(1 - p, 5),
    outBack: p => { const c = 1.9; return 1 + (c + 1) * Math.pow(p - 1, 3) + c * Math.pow(p - 1, 2); },
    outElastic: p => (p <= 0 ? 0 : p >= 1 ? 1 : Math.pow(2, -9 * p) * Math.sin((p * 10 - 0.75) * 2.1) + 1),
  };
  const ease = (name, p) => (E[name] || E.outCubic)(clamp(p));
  const stagger = (t, i, delay, dur) => clamp((t - delay * i) / dur);
  function mulberry(seed) {
    let a = seed >>> 0 || 1;
    return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }
  const SEED = (spec.seed == null ? 1337 : spec.seed) >>> 0;
  const rnd = mulberry(SEED);

  const rgba = (hex, a) => {
    const h = hex.replace('#', '');
    const n = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
    const v = parseInt(n, 16);
    return `rgba(${(v >> 16) & 255},${(v >> 8) & 255},${v & 255},${a})`;
  };
  const font = (weight, size, fam = 'inter') => `${weight} ${Math.round(size)}px ${fam}, "DejaVu Sans", sans-serif`;

  /* -------------------------------------------------------------- timeline */
  const scenes = (spec.scenes || []).filter(Boolean);
  if (!scenes.length) { window.__error = 'spec.scenes is empty'; return; }
  let clock = 0;
  for (const s of scenes) {
    s._start = clock; s._duration = Math.max(0.4, s.duration || 2.5); s._end = clock + s._duration; clock = s._end;
  }
  if (spec.loop !== false) { scenes.push({kind: 'brandcard', _noFooter: true, duration: spec.loopSeconds || 0.8, transition: 'dissolve', _start: clock, _end: clock + (spec.loopSeconds || 0.8), _duration: spec.loopSeconds || 0.8}); clock += spec.loopSeconds || 0.8; }
  const DURATION = clock;
  const NFRAMES = Math.max(2, Math.round(DURATION * FPS));

  const transDur = s => {
    const t = s.transition;
    if (!t) return 0;
    if (typeof t === 'object') return t.dur == null ? 0.4 : t.dur;
    return 0.4;
  };
  const transKind = s => (typeof s.transition === 'object' ? s.transition.type || 'dissolve' : s.transition) || 'dissolve';

  /* --------------------------------------------------------------- canvas */
  const canvas = document.createElement('canvas');
  canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext('2d', {alpha: false});
  const sheet = document.createElement('canvas');
  const sctx = sheet.getContext('2d');

  /* ---------------------------------------------------------- background fx */
  const GRAIN_TILES = [];
  for (let i = 0; i < 4; i++) {
    const c = document.createElement('canvas'); c.width = c.height = 160;
    const g = c.getContext('2d'); const img = g.createImageData(160, 160); const r = mulberry(1000 + i * 77);
    for (let p = 0; p < img.data.length; p += 4) {
      const v = 110 + r() * 90 | 0;
      img.data[p] = img.data[p + 1] = img.data[p + 2] = v; img.data[p + 3] = 255;
    }
    g.putImageData(img, 0, 0); GRAIN_TILES.push(c);
  }

  function drawBackground(t, frame) {
    const [a, b] = P.bg;
    const g = ctx.createLinearGradient(0, 0, W * 0.35, H);
    g.addColorStop(0, a); g.addColorStop(1, b);
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);

    const drift = spec.bgMotion === false ? 0 : 1;
    const glows = [
      {c: P.accent, x: 0.24 + 0.10 * Math.sin(t * 0.55), y: 0.20 + 0.08 * Math.cos(t * 0.4), r: 0.62, a: 0.20},
      {c: P.accent2, x: 0.80 + 0.09 * Math.cos(t * 0.42), y: 0.78 + 0.07 * Math.sin(t * 0.5), r: 0.55, a: 0.17},
    ];
    for (const gl of glows) {
      const rr = gl.r * Math.max(W, H) * 0.9;
      const rg = ctx.createRadialGradient(gl.x * W + drift * 0, gl.y * H, 0, gl.x * W, gl.y * H, rr);
      rg.addColorStop(0, rgba(gl.c, gl.a)); rg.addColorStop(0.55, rgba(gl.c, gl.a * 0.25)); rg.addColorStop(1, rgba(gl.c, 0));
      ctx.fillStyle = rg; ctx.fillRect(0, 0, W, H);
    }
    if (spec.grid) {
      ctx.save(); ctx.globalAlpha = 0.05; ctx.strokeStyle = P.fg; ctx.lineWidth = 1;
      const step = 64 * U;
      for (let x = 0; x < W; x += step) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
      for (let y = 0; y < H; y += step) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
      ctx.restore();
    }
  }

  function drawGrainVignette(frame, t) {
    if (spec.grain !== false) {
      const tile = GRAIN_TILES[frame & 3];
      ctx.save();
      ctx.globalCompositeOperation = 'overlay';
      ctx.globalAlpha = 0.055;
      const ox = (frame * 37) % 160, oy = (frame * 53) % 160;
      for (let x = -ox; x < W; x += 160) for (let y = -oy; y < H; y += 160) ctx.drawImage(tile, x, y);
      ctx.restore();
    }
    const vg = ctx.createRadialGradient(W / 2, H / 2, Math.min(W, H) * 0.32, W / 2, H / 2, Math.max(W, H) * 0.78);
    vg.addColorStop(0, 'rgba(0,0,0,0)'); vg.addColorStop(1, 'rgba(0,0,0,0.42)');
    ctx.fillStyle = vg; ctx.fillRect(0, 0, W, H);
    if (spec.scanlines) {
      ctx.save(); ctx.globalAlpha = 0.06; ctx.fillStyle = '#000';
      for (let y = 0; y < H; y += 3 * U) ctx.fillRect(0, y, W, Math.max(1, U));
      ctx.restore();
    }
  }

  /* ------------------------------------------------------------ text utils */
  function layout(text, maxW, weight, size, fam, lineHeight = 1.06) {
    const f = font(weight, size, fam);
    ctx.font = f;
    const out = [];
    for (const para of String(text).split('\n')) {
      const words = para.split(/\s+/).filter(Boolean);
      if (!words.length) { out.push(''); continue; }
      let line = words[0];
      for (let i = 1; i < words.length; i++) {
        const test = line + ' ' + words[i];
        if (ctx.measureText(test).width > maxW && line) { out.push(line); line = words[i]; } else line = test;
      }
      out.push(line);
    }
    return {lines: out, size, lineHeight, width: Math.max(...out.map(l => ctx.measureText(l).width), 0), height: out.length * size * lineHeight};
  }

  function fitLines(text, maxW, maxSize, minSize, weight, fam, lineHeight) {
    let size = maxSize;
    let L = layout(text, maxW, weight, size, fam, lineHeight);
    while (size > minSize && L.lines.length > 2 && L.width > maxW) {
      size -= Math.max(1, size * 0.04);
      L = layout(text, maxW, weight, size, fam, lineHeight);
    }
    return L;
  }

  function drawLines(L, x, y, color, opts = {}) {
    const {align = 'left', weight = 700, fam = 'display', alpha = 1, shadow = 0, tracking = 0, baseline = 'top'} = opts;
    ctx.save();
    ctx.font = font(weight, L.size, fam);
    ctx.fillStyle = color; ctx.textAlign = align; ctx.textBaseline = baseline;
    ctx.globalAlpha = alpha;
    if (tracking) ctx.letterSpacing = `${tracking * L.size}px`;
    if (shadow) { ctx.shadowColor = rgba(shadow === true ? P.accent : shadow, 0.45); ctx.shadowBlur = L.size * 0.42; }
    L.lines.forEach((line, i) => ctx.fillText(line, x, y + i * L.size * L.lineHeight));
    if (tracking) ctx.letterSpacing = '0px';
    ctx.restore();
  }

  // text that rises out from behind a mask — the house reveal
  function revealLines(L, x, y, p, color, opts = {}) {
    if (p <= 0) return;
    const e = ease(opts.ease || 'outExpo', p);
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, y - L.size * 0.35, W, L.height * e + L.size * 0.6);
    ctx.clip();
    drawLines(L, x, y + (1 - e) * L.size * 0.5, color, Object.assign({}, opts, {alpha: clamp(p * 2.2)}));
    ctx.restore();
  }

  function kicker(text, x, y, p, color, size = 22 * U) {
    if (!text) return;
    const e = ease('outCubic', p);
    ctx.save();
    ctx.font = font(600, size, 'inter');
    ctx.letterSpacing = `${size * 0.22}px`;
    ctx.fillStyle = color || P.accent;
    ctx.textBaseline = 'top';
    ctx.globalAlpha = clamp(p * 2);
    ctx.fillText(String(text).toUpperCase(), x + (1 - e) * -14 * U, y + (1 - e) * 8 * U);
    ctx.letterSpacing = '0px';
    ctx.restore();
  }

  function chip(text, x, y, opts = {}) {
    const {size = 24 * U, color = P.fg, border = rgba(P.fg, 0.16), bg = rgba(P.fg, 0.05), fam = 'mono', padX = 16 * U, padY = 9 * U, align = 'left'} = opts;
    ctx.save();
    ctx.font = font(opts.weight || 500, size, fam);
    const tw = ctx.measureText(text).width;
    const w = tw + padX * 2, h = size * 1.5 + padY * 2;
    const cx = align === 'center' ? x - w / 2 : x;
    roundRect(ctx, cx, y, w, h, h / 2);
    ctx.fillStyle = bg; ctx.fill();
    if (border) { ctx.strokeStyle = border; ctx.lineWidth = Math.max(1, 1.5 * U); ctx.stroke(); }
    ctx.fillStyle = color; ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
    ctx.fillText(text, cx + padX, y + h / 2 + size * 0.06);
    ctx.restore();
    return {w, h, x: cx, y};
  }

  function roundRect(c, x, y, w, h, r) {
    const rr = Math.min(r, w / 2, h / 2);
    c.beginPath();
    c.moveTo(x + rr, y);
    c.arcTo(x + w, y, x + w, y + h, rr);
    c.arcTo(x + w, y + h, x, y + h, rr);
    c.arcTo(x, y + h, x, y, rr);
    c.arcTo(x, y, x + w, y, rr);
    c.closePath();
  }

  function panel(x, y, w, h, opts = {}) {
    const r = opts.r == null ? 26 * U : opts.r;
    roundRect(ctx, x, y, w, h, r);
    if (opts.fill !== null) { ctx.fillStyle = opts.fill || rgba(P.fg, 0.045); ctx.fill(); }
    if (opts.stroke !== null) { ctx.strokeStyle = opts.stroke || rgba(P.fg, 0.12); ctx.lineWidth = Math.max(1, 1.4 * U); ctx.stroke(); }
    if (opts.glow) { ctx.save(); ctx.shadowColor = rgba(P.accent, 0.5); ctx.shadowBlur = 30 * U; ctx.fillStyle = rgba(P.accent, 0.10); ctx.fill(); ctx.restore(); }
  }

  const M = () => ({x: isTall ? 78 * U : 168 * U, top: isTall ? 190 * U : 120 * U, right: isTall ? 78 * U : 168 * U, bottom: isTall ? 150 * U : 110 * U});
  // Vertically centre a block of known height, biased slightly above the middle.
  const blockTop = (contentH, bias = 0.44) => Math.max(M().top * 0.68, (H - contentH) * bias);

  function footer(S, t) {
    if (!spec.repo) return;
    const p = ease('outCubic', seg(t, 0.15, 0.6));
    const m = M();
    ctx.save();
    ctx.globalAlpha = p * 0.85;
    ctx.font = font(500, 20 * U, 'mono');
    ctx.fillStyle = P.muted; ctx.textBaseline = 'bottom'; ctx.textAlign = 'right';
    ctx.letterSpacing = `${2 * U}px`;
    ctx.fillText(spec.repo, W - m.x, H - m.bottom * 0.55);
    ctx.letterSpacing = '0px';
    ctx.restore();
  }

  /* ------------------------------------------------------------ scene kinds */
  const KINDS = {};

  KINDS.title = (c, S, T) => {
    const m = M();
    const maxW = W - m.x - m.right;
    const kH = S.kicker ? 52 * U : 0;
    const L = S.headline ? fitLines(S.headline, maxW, (S.size || 132) * U, 34 * U, S.weight || 800, 'display', 1.02) : null;
    const subL = S.sub ? layout(S.sub, Math.min(maxW, (S.subWidth || 0.62) * W), 400, 32 * U, 'inter', 1.35) : null;
    const ruleH = S.rule !== false && S.headline ? 40 * U : 0;
    const badgeH = S.badge ? 62 * U : 0;
    const total = kH + (L ? L.height + 26 * U : 0) + ruleH + (subL ? subL.height + 22 * U : 0) + badgeH;
    let y = S.top ? m.top : Math.max(m.top * 0.72, (H - total) * (S.bias || 0.44));
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.4)); y += kH; }
    if (L) {
      const p = seg(T, 0.12, 0.75);
      revealLines(L, m.x, y, p, S.color || P.fg, {align: 'left', weight: S.weight || 800, fam: 'display', shadow: S.glow ? P.accent : 0});
      y += L.height + 26 * U;
      if (ruleH) {
        const rp = ease('outExpo', seg(T, 0.55, 1.0));
        ctx.save(); ctx.fillStyle = P.accent;
        ctx.fillRect(m.x, y, Math.min(260 * U, L.width) * rp, 7 * U);
        ctx.restore();
        y += 40 * U;
      }
    }
    if (subL) {
      revealLines(subL, m.x, y, seg(T, 0.45, 1.0), P.muted, {weight: 400, fam: 'inter'});
      y += subL.height + 22 * U;
    }
    if (S.badge) {
      ctx.save(); ctx.globalAlpha = clamp(seg(T, 0.7, 0.85));
      chip(S.badge, m.x, y, {size: 24 * U, color: P.accent, border: rgba(P.accent, 0.4), bg: rgba(P.accent, 0.08)});
      ctx.restore();
    }
    if (S.repo) {
      ctx.save(); ctx.globalAlpha = clamp(seg(T, 0.8, 1.05));
      chip(S.repo, W - m.x, m.top, {size: 24 * U, color: P.muted, align: 'right'});
      ctx.restore();
    }
  };

  KINDS.brandcard = (c, S, T) => {
    const m = M();
    // Bottom-anchored end plate: it must never collide with centred outro text, and
    // the hard cut back to frame 0 stays readable.
    const L = layout(spec.repo || spec.title || '', W - 2 * m.x, 800, (spec.brandSize || 54) * U, 'display', 1.05);
    const p = ease('outCubic', seg(T, 0, 0.35));
    const cy = H - m.bottom - 40 * U;
    ctx.save(); ctx.globalAlpha = 0.95 * p;
    ctx.strokeStyle = P.accent; ctx.lineWidth = 6 * U; ctx.lineCap = 'round';
    ctx.beginPath(); ctx.arc(W / 2 - L.width / 2 - 34 * U, cy - L.height / 2 + L.size * 0.34, 12 * U, 0, Math.PI * 2); ctx.stroke();
    ctx.restore();
    drawLines(L, W / 2 + 14 * U, cy - L.height / 2, P.fg, {align: 'center', weight: 800, fam: 'display', alpha: p});
    if (spec.tagline) {
      const s = layout(spec.tagline, W * 0.8, 500, 26 * U, 'inter', 1.3);
      drawLines(s, W / 2, cy + L.height / 2 + 14 * U, P.muted, {align: 'center', weight: 500, fam: 'inter', alpha: p * 0.9});
    }
  };

  const fmtNumber = (v, o = {}) => {
    const {decimals = 0, comma = true, prefix = '', suffix = ''} = o;
    let n = v;
    if (o.abbrev && Math.abs(v) >= 1000) {
      const k = v / 1000;
      return prefix + (comma ? k.toLocaleString('en-US', {minimumFractionDigits: Math.abs(k) < 10 ? 1 : 0, maximumFractionDigits: 1}) : k.toFixed(1)) + 'k' + suffix;
    }
    const s = comma ? n.toLocaleString('en-US', {minimumFractionDigits: decimals, maximumFractionDigits: decimals}) : n.toFixed(decimals);
    return prefix + s + suffix;
  };

  KINDS.stat = (c, S, T) => {
    const m = M();
    const p = ease('outExpo', seg(T, 0.1, 0.95));
    const target = typeof S.value === 'number' ? S.value : (parseFloat(S.value) || 0);
    const shown = S.text || fmtNumber(target * p, S);
    const items = S.items || null;
    if (S.ring) {
      const r = Math.min(W, H) * 0.19;
      const cxr = W / 2, cyr = H * 0.44;
      ctx.save();
      ctx.lineWidth = 10 * U; ctx.lineCap = 'round';
      ctx.strokeStyle = rgba(P.fg, 0.08);
      ctx.beginPath(); ctx.arc(cxr, cyr, r, 0, Math.PI * 2); ctx.stroke();
      ctx.strokeStyle = P.accent; ctx.shadowColor = rgba(P.accent, 0.6); ctx.shadowBlur = 26 * U;
      ctx.beginPath(); ctx.arc(cxr, cyr, r, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * p); ctx.stroke();
      ctx.restore();
      const Lr = fitLines(shown, r * 1.7, (S.size || 120) * U, 30 * U, 900, 'display', 1.0);
      drawLines(Lr, cxr, cyr - Lr.height / 2, P.fg, {align: 'center', weight: 900, fam: 'display', alpha: clamp(T * 4)});
      if (S.label) {
        const sl = layout(S.label, W * 0.7, 600, 40 * U, 'inter', 1.2);
        revealLines(sl, cxr, cyr + r + 56 * U, seg(T, 0.35, 0.85), P.accent, {align: 'center', weight: 600, fam: 'inter'});
      }
      return;
    }
    const kH = S.kicker ? 48 * U : 0;
    const L = fitLines(shown, W - m.x - m.right, (S.size || 210) * U, 40 * U, 900, 'display', 1.0);
    const labelL = S.label ? layout(S.label, W * 0.7, 600, 40 * U, 'inter', 1.2) : null;
    const subL = S.sub ? layout(S.sub, W * 0.6, 400, 27 * U, 'inter', 1.35) : null;
    const total = kH + L.height + (labelL ? labelL.height + 18 * U : 0) + (subL ? subL.height : 0);
    let y = S.top ? m.top : Math.max(m.top * 0.7, (H - total) * (S.bias || 0.42));
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.35), P.accent); y += kH; }
    revealLines(L, m.x, y, seg(T, 0.08, 0.6), P.fg, {weight: 900, fam: 'display', shadow: S.glow ? P.accent : 0});
    y += L.height + 18 * U;
    if (labelL) { revealLines(labelL, m.x, y, seg(T, 0.35, 0.85), P.accent, {weight: 600, fam: 'inter'}); y += labelL.height; }
    if (subL) { revealLines(subL, m.x, y + 14 * U, seg(T, 0.5, 0.95), P.muted, {weight: 400, fam: 'inter'}); }
    if (items) {
      const n = items.length, gap = 40 * U;
      const cw = (W - m.x - m.right - gap * (n - 1)) / n;
      const chh = 104 * U;
      const yy = H - m.bottom - chh;
      items.forEach((it, i) => {
        const st = 0.55 + i * 0.09;
        ctx.save(); ctx.globalAlpha = clamp(seg(T, st, st + 0.25));
        const x = m.x + i * (cw + gap);
        const p2 = ease('outExpo', seg(T, st, st + 0.55));
        ctx.translate(0, (1 - p2) * 24 * U);
        panel(x, yy, cw, chh, {fill: rgba(P.fg, 0.05), stroke: rgba(P.fg, 0.1), r: 18 * U});
        const v = layout(it.text != null ? it.text : fmtNumber((Number(it.value) || 0) * p2, it), cw * 0.86, 800, 40 * U, 'display', 1.0);
        drawLines(v, x + 22 * U, yy + 16 * U, i === 0 ? P.accent : P.fg, {weight: 800, fam: 'display'});
        const l = layout(it.label, cw * 0.86, 500, 20 * U, 'inter', 1.2);
        drawLines(l, x + 22 * U, yy + 62 * U, P.muted, {weight: 500, fam: 'inter'});
        ctx.restore();
      });
    }
  };

  KINDS.features = (c, S, T) => {
    const m = M();
    const items = S.items || [];
    const cols = S.cols || (items.length <= 3 ? items.length : 3);
    const rows = Math.ceil(items.length / cols);
    const kH = S.kicker ? 46 * U : 0;
    const headL = S.headline ? layout(S.headline, W - m.x - m.right, 800, (S.size || 64) * U, 'display', 1.06) : null;
    const headGap = headL ? (isTall ? 56 * U : 44 * U) : 0;
    const gapX = 30 * U, gapY = 26 * U;
    const cw = (W - m.x - m.right - gapX * (cols - 1)) / cols;
    const headerH = kH + (headL ? headL.height + headGap : 0);
    const ch = Math.min((H - m.bottom - headerH - gapY * (rows - 1)) / rows, S.cardH ? S.cardH * U : 250 * U);
    let y = S.top ? m.top : blockTop(headerH + rows * ch + (rows - 1) * gapY, S.bias || 0.44);
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.35)); y += kH; }
    if (headL) {
      revealLines(headL, m.x, y, seg(T, 0.1, 0.55), P.fg, {weight: 800, fam: 'display'});
      y += headL.height + headGap;
    }
    const sweep = ease('inOutCubic', seg(T, S.sweepAt == null ? 0.8 : S.sweepAt, (S.sweepAt == null ? 0.8 : S.sweepAt) + 0.6));
    items.forEach((it, i) => {
      const col = i % cols, row = Math.floor(i / cols);
      const p = ease('outBack', stagger(T, i, 0.1, 0.55));
      const x = m.x + col * (cw + gapX), yy = y + row * (ch + gapY);
      ctx.save();
      ctx.globalAlpha = clamp(seg(T, 0.12 + i * 0.1, 0.3 + i * 0.1));
      ctx.translate(x + cw / 2, yy + ch / 2);
      ctx.scale(lerp(0.94, 1, p), lerp(0.94, 1, p));
      ctx.translate(-cw / 2, -ch / 2);
      panel(0, 0, cw, ch, {fill: rgba(P.fg, 0.045), stroke: rgba(P.fg, 0.11), r: 24 * U, glow: it.hot});
      if (it.hot) { roundRect(ctx, 0, 0, cw, ch, 24 * U); ctx.strokeStyle = rgba(P.accent, 0.5); ctx.lineWidth = 2 * U; ctx.stroke(); }
      if (sweep > 0 && sweep < 1) {
        const sx = lerp(-cw * 0.6, cw * 1.2, sweep);
        const g = ctx.createLinearGradient(x + sx - 120 * U, 0, x + sx + 120 * U, ch);
        g.addColorStop(0, rgba(P.accent2, 0)); g.addColorStop(0.5, rgba(P.accent2, 0.16)); g.addColorStop(1, rgba(P.accent2, 0));
        ctx.save(); roundRect(ctx, 0, 0, cw, ch, 24 * U); ctx.clip();
        ctx.fillStyle = g; ctx.fillRect(0, 0, cw, ch); ctx.restore();
      }
      const pad = 26 * U;
      const bodySize = isTall ? 25 * U : 23 * U;
      let ty = pad;
      if (it.tag) {
        ctx.font = font(700, 19 * U, 'mono'); ctx.fillStyle = P.accent; ctx.textBaseline = 'top';
        ctx.fillText(String(it.tag).toUpperCase(), pad, ty); ty += 34 * U;
      }
      const tl = layout(it.title, cw - pad * 2, 700, (S.titleSize || 34) * U, 'inter', 1.15);
      ctx.font = font(700, tl.size, 'inter'); ctx.fillStyle = P.fg; ctx.textBaseline = 'top';
      tl.lines.forEach((l, k) => ctx.fillText(l, pad, ty + k * tl.size * tl.lineHeight));
      ty += tl.height + 12 * U;
      if (it.body) {
        const bl = layout(it.body, cw - pad * 2, 400, bodySize, 'inter', 1.32);
        ctx.font = font(400, bl.size, 'inter'); ctx.fillStyle = P.muted;
        const maxLines = Math.max(1, Math.floor((ch - ty - pad) / (bl.size * bl.lineHeight)));
        bl.lines.slice(0, maxLines).forEach((l, k) => ctx.fillText(l, pad, ty + k * bl.size * bl.lineHeight));
      }
      ctx.restore();
    });
  };

  KINDS.code = (c, S, T) => {
    const m = M();
    const lines = S.lines || [];
    const fs = (S.fontSize || 28) * U, lh = fs * 1.62;
    const w = W - m.x - m.right;
    const h = 74 * U + lines.length * lh + (S.status ? 64 * U : 24 * U);
    const kH = S.kicker ? 40 * U : 0;
    const headL = S.headline ? layout(S.headline, W - m.x - m.right, 800, (S.size || 58) * U, 'display', 1.05) : null;
    const headerH = kH + (headL ? headL.height + 30 * U : 0);
    let y = S.top ? m.top : blockTop(headerH + h, S.bias || 0.44);
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += kH; }
    if (headL) {
      revealLines(headL, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += headL.height + 30 * U;
    }
    const y0 = Math.min(y, H - m.bottom - h);
    // A terminal is dark on every palette: on light slides a translucent panel
    // turns muddy and the code colours stop reading. Ink + its own greys instead.
    const TERM = {bg: 'rgba(20,19,25,0.96)', bar: 'rgba(255,255,255,0.06)', rule: 'rgba(255,255,255,0.14)',
                  title: '#9aa0ae', dim: '#a9aeb9', stroke: 'rgba(255,255,255,0.13)'};
    ctx.save();
    ctx.globalAlpha = clamp(seg(T, 0.05, 0.3));
    panel(m.x, y0, w, h, {fill: TERM.bg, stroke: TERM.stroke, r: 22 * U});
    ctx.restore();
    // chrome bar
    ctx.save();
    ctx.beginPath(); roundRect(ctx, m.x, y0, w, 54 * U, 22 * U); ctx.clip();
    ctx.fillStyle = TERM.bar; ctx.fillRect(m.x, y0, w, 54 * U);
    ctx.fillStyle = TERM.rule; ctx.fillRect(m.x, y0 + 53 * U, w, 1.5 * U);
    ctx.restore();
    const dots = ['#ff5f57', '#febc2e', '#28c840'];
    dots.forEach((d, i) => {
      ctx.beginPath(); ctx.arc(m.x + 30 * U + i * 24 * U, y0 + 27 * U, 8 * U, 0, Math.PI * 2);
      ctx.fillStyle = rgba(d, 0.85); ctx.fill();
    });
    ctx.font = font(500, 21 * U, 'mono'); ctx.fillStyle = TERM.title; ctx.textBaseline = 'middle'; ctx.textAlign = 'center';
    ctx.fillText(S.window || 'terminal', m.x + w / 2, y0 + 28 * U);
    ctx.textAlign = 'left';

    const x0 = m.x + 34 * U, yTop = y0 + 54 * U + 26 * U;
    const revealAll = ease('linear', seg(T, 0.3, 0.3 + lines.length * 0.09));
    lines.forEach((line, i) => {
      const p = clamp(seg(revealAll, i / lines.length, (i + 1) / lines.length));
      if (p <= 0) return;
      const ly = yTop + i * lh;
      if (S.highlight === i) {
        ctx.save(); ctx.fillStyle = rgba(P.accent, 0.2); roundRect(ctx, m.x + 14 * U, ly - 5 * U, w - 28 * U, lh, 10 * U); ctx.fill();
        ctx.fillStyle = P.accent; ctx.fillRect(m.x + 14 * U, ly - 5 * U, 4 * U, lh); ctx.restore();
      }
      ctx.font = font(400, fs, 'mono'); ctx.textBaseline = 'top';
      let x = x0;
      const parts = Array.isArray(line) ? line : [[line, 'plain']];
      const shownChars = Math.ceil(p * parts.reduce((n, pr) => n + String(pr[0]).length, 0));
      let left = shownChars;
      for (const [text, color] of parts) {
        const str = String(text); const take = clamp(left, 0, str.length); left -= take;
        if (take <= 0) break;
        ctx.fillStyle = CODE_COLORS[color] || P.fg;
        ctx.fillText(str.slice(0, take), x, ly);
        x += ctx.measureText(str.slice(0, take)).width;
      }
    });
    if (S.status && T > 0.3 + lines.length * 0.09) {
      const p = clamp(seg(T, 0.3 + lines.length * 0.09, 0.3 + lines.length * 0.09 + 0.3));
      ctx.save(); ctx.globalAlpha = p;
      ctx.font = font(500, fs * 0.86, 'mono'); ctx.textBaseline = 'top';
      ctx.fillStyle = P.accent; ctx.fillText('●', m.x + 34 * U, y0 + h - 44 * U);
      ctx.fillStyle = TERM.dim; ctx.fillText(String(S.status), m.x + 58 * U, y0 + h - 44 * U);
      ctx.restore();
    }
    if (S.caret !== false) {
      const lastShown = revealAll * lines.length;
      const li = Math.min(lines.length - 1, Math.max(0, Math.floor(lastShown)));
      const partial = lastShown - li;
      const ly = yTop + li * lh;
      const parts = Array.isArray(lines[li]) ? lines[li] : [[lines[li], 'plain']];
      let x = x0;
      for (const [text] of parts) { const str = String(text); const take = clamp(partial, 0, str.length); x += ctx.measureText(str.slice(0, take)).width; }
      if (Math.floor(T * 2.2) % 2 === 0 && T < 0.3 + lines.length * 0.09 + 0.2) {
        ctx.fillStyle = P.accent; ctx.fillRect(x + 4 * U, ly + 2 * U, fs * 0.55, fs * 1.1);
      }
    }
  };

  KINDS.bars = (c, S, T) => {
    const m = M();
    const items = S.items || [];
    const kH = S.kicker ? 42 * U : 0;
    const headL = S.headline ? layout(S.headline, W - m.x - m.right, 800, (S.size || 62) * U, 'display', 1.05) : null;
    const subL = S.sub ? layout(S.sub, W * 0.6, 400, 26 * U, 'inter', 1.3) : null;
    const headerH = kH + (headL ? headL.height + (isTall ? 60 * U : 46 * U) : 0) + (subL ? subL.height + 30 * U : 0);
    const n = Math.max(1, items.length);
    const bh = Math.min(58 * U, (H - m.top - m.bottom - headerH) / n * 0.62);
    const gap = Math.max(14 * U, bh * 0.5);
    let y = S.top ? m.top : blockTop(headerH + n * bh + (n - 1) * gap, S.bias || 0.44);
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += kH; }
    if (headL) {
      revealLines(headL, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += headL.height + (isTall ? 60 * U : 46 * U);
    }
    if (subL) {
      revealLines(subL, m.x, y, seg(T, 0.2, 0.6), P.muted, {weight: 400, fam: 'inter'});
      y += subL.height + 30 * U;
    }
    const maxV = Math.max(...items.map(i => i.value), 1);
    const labelW = (S.labelWidth || 190) * U;
    const valueW = 150 * U;
    const trackX = m.x + labelW, trackW = W - m.x - m.right - trackX - valueW;
    items.forEach((it, i) => {
      const p = ease('outExpo', stagger(T, i, 0.12, 0.75));
      const yy = y + i * (bh + gap);
      const w = Math.max(4 * U, trackW * (it.value / maxV) * p);
      ctx.save();
      ctx.font = font(500, 24 * U, 'mono'); ctx.fillStyle = i === 0 ? P.fg : P.muted;
      ctx.textBaseline = 'middle'; ctx.textAlign = 'left';
      ctx.fillText(it.label, m.x, yy + bh / 2);
      roundRect(ctx, trackX, yy, trackW, bh, bh / 2);
      ctx.fillStyle = rgba(P.fg, 0.06); ctx.fill();
      const g = ctx.createLinearGradient(trackX, 0, trackX + Math.max(w, bh), 0);
      const hot = i === 0;
      g.addColorStop(0, rgba(hot ? P.accent : P.muted, hot ? 0.95 : 0.45));
      g.addColorStop(1, rgba(hot ? P.accent2 : P.muted, hot ? 0.95 : 0.25));
      ctx.save(); roundRect(ctx, trackX, yy, w, bh, bh / 2); ctx.clip();
      ctx.fillStyle = g; ctx.fillRect(trackX, yy, w, bh);
      if (hot) { ctx.shadowColor = rgba(P.accent, 0.5); ctx.shadowBlur = 22 * U; ctx.fillRect(trackX, yy, w, bh); }
      ctx.restore();
      ctx.font = font(700, 26 * U, 'mono'); ctx.fillStyle = hot ? P.accent : P.muted; ctx.textAlign = 'left';
      ctx.fillText(it.display || fmtNumber(it.value * (it.value / maxV) * (it.max || 1) * p, it), trackX + trackW + 22 * U, yy + bh / 2 + 1);
      ctx.restore();
    });
  };

  KINDS.flow = (c, S, T) => {
    const m = M();
    const nodes = S.nodes || [];
    const headGuess = S.headline ? 70 * U + 52 * U : 0;
    let y = S.top ? m.top : blockTop((S.kicker ? 42 * U : 0) + headGuess + 120 * U, S.bias || 0.42);
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += 42 * U; }
    if (S.headline) {
      const L = layout(S.headline, W - m.x - m.right, 800, (S.size || 60) * U, 'display', 1.05);
      revealLines(L, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += L.height + (isTall ? 70 * U : 52 * U);
    }
    const vertical = S.dir === 'down' || nodes.length > 4 && isTall;
    const nw = vertical ? (W - m.x - m.right) : Math.min(280 * U, (W - m.x - m.right - (nodes.length - 1) * 40 * U) / nodes.length);
    const nh = 120 * U;
    const cx0 = vertical ? m.x : m.x, cy0 = y;
    nodes.forEach((nd, i) => {
      const p = ease('outBack', stagger(T, i, 0.12, 0.5));
      const x = vertical ? cx0 : cx0 + i * (nw + 40 * U);
      const yy = vertical ? cy0 + i * (nh + 62 * U) : cy0;
      ctx.save();
      ctx.globalAlpha = clamp(seg(T, 0.1 + i * 0.12, 0.35 + i * 0.12));
      ctx.translate(x + nw / 2, yy + nh / 2); ctx.scale(lerp(0.9, 1, p), lerp(0.9, 1, p)); ctx.translate(-nw / 2, -nh / 2);
      panel(0, 0, nw, nh, {fill: rgba(P.fg, 0.05), stroke: rgba(nd.hot || i === nodes.length - 1 ? P.accent : P.fg, nd.hot || i === nodes.length - 1 ? 0.55 : 0.12), r: 20 * U, glow: nd.hot});
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      const l1 = layout(nd.label, nw - 30 * U, 700, 28 * U, 'inter', 1.1);
      const l2 = nd.sub ? layout(nd.sub, nw - 30 * U, 400, 20 * U, 'mono', 1.2) : null;
      const totalH = l1.height + (l2 ? l2.height + 8 * U : 0);
      let ty = (nh - totalH) / 2;
      drawLines(l1, nw / 2, ty, P.fg, {align: 'center', weight: 700, fam: 'inter'});
      if (l2) drawLines(l2, nw / 2, ty + l1.height + 8 * U, P.muted, {align: 'center', weight: 400, fam: 'mono'});
      ctx.restore();
      // connector
      if (i < nodes.length - 1) {
        const cp = ease('inOutCubic', clamp((T - 0.25 - i * 0.12) / 0.45));
        if (cp > 0) {
          const pts = vertical
            ? [[x + nw / 2, yy + nh], [x + nw / 2, yy + nh + 62 * U]]
            : [[x + nw, yy + nh / 2], [x + nw + 40 * U, yy + nh / 2]];
          ctx.save();
          ctx.strokeStyle = rgba(P.accent, 0.7); ctx.lineWidth = 2.5 * U; ctx.lineCap = 'round';
          ctx.setLineDash([]);
          ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
          const full = Math.hypot(pts[1][0] - pts[0][0], pts[1][1] - pts[0][1]);
          const l = full * cp;
          ctx.lineTo(pts[0][0] + (pts[1][0] - pts[0][0]) * cp, pts[0][1] + (pts[1][1] - pts[0][1]) * cp);
          ctx.stroke();
          const travel = ((T * 0.9 + i * 0.25) % 1);
          if (travel < cp) {
            const px = lerp(pts[0][0], pts[1][0], travel), py = lerp(pts[0][1], pts[1][1], travel);
            ctx.fillStyle = P.accent2; ctx.shadowColor = P.accent2; ctx.shadowBlur = 18 * U;
            ctx.beginPath(); ctx.arc(px, py, 6 * U, 0, Math.PI * 2); ctx.fill();
          }
          ctx.restore();
        }
      }
    });
  };

  KINDS.commits = (c, S, T) => {
    const m = M();
    // Trim empty weeks at the old end so a young repo shows 3 weeks, not 26 blank ones.
    let grid = S.grid || [];
    while (grid.length > 2 && grid[0].every(v => !v)) grid = grid.slice(1);
    if (grid.length > 30) grid = grid.slice(grid.length - 30);
    const kH = S.kicker ? 44 * U : 0;
    const headL = S.headline ? layout(S.headline, W - m.x - m.right, 800, (S.size || 60) * U, 'display', 1.05) : null;
    const headGap = headL ? (isTall ? 70 * U : 44 * U) : 0;
    const weeks = grid.length, days = grid[0] ? grid[0].length : 7;
    const gap = 5 * U;
    const maxW = W - m.x - m.right;
    const cell = S.cell ? S.cell * U : Math.min(34 * U, (maxW - (weeks - 1) * gap) / weeks);
    const gh = days * (cell + gap) - gap;
    const statL = S.stat ? layout(S.stat, W * 0.7, 700, 34 * U, 'inter', 1.2) : null;
    const statH = S.stat ? statL.height : 52 * U;
    let y = S.top ? m.top : blockTop(kH + (headL ? headL.height + headGap : 0) + gh + 40 * U + statH, S.bias || 0.44);
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += kH; }
    if (headL) {
      revealLines(headL, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += headL.height + headGap;
    }
    const total = grid.flat().reduce((a, b) => a + b, 0);
    const wDelay = weeks > 30 ? 0.012 : 0.03;
    for (let wI = 0; wI < weeks; wI++) {
      for (let d = 0; d < days; d++) {
        const v = grid[wI][d] || 0;
        const p = ease('outBack', stagger(T, wI, wDelay, 0.4));
        if (p <= 0) continue;
        const x = m.x + wI * (cell + gap), yy = y + d * (cell + gap);
        ctx.save();
        ctx.globalAlpha = clamp(seg(T, 0.1 + wI * wDelay, 0.32 + wI * wDelay));
        const lvl = v / 4;
        roundRect(ctx, x, yy, cell * p, cell * p, cell * 0.28);
        ctx.fillStyle = v === 0 ? rgba(P.fg, 0.05) : rgba(P.accent, 0.16 + lvl * 0.84);
        ctx.fill();
        ctx.restore();
      }
    }
    const ty = y + gh + 40 * U;
    if (statL) {
      revealLines(statL, m.x, ty, seg(T, 0.4, 0.8), P.accent, {weight: 700, fam: 'inter'});
    } else {
      const shown = Math.round(total * ease('outExpo', seg(T, 0.3, 0.9)));
      const L = layout(`${shown.toLocaleString('en-US')} ${S.unit || 'commits'}`, W * 0.7, 800, 46 * U, 'display', 1.1);
      revealLines(L, m.x, ty, seg(T, 0.35, 0.8), P.fg, {weight: 800, fam: 'display'});
    }
    if (S.legend !== false) {
      ctx.save(); ctx.font = font(500, 19 * U, 'mono'); ctx.fillStyle = P.muted; ctx.textBaseline = 'top';
      const lx = W - m.right - 5 * (cell * 0.7 + 8 * U);
      ctx.fillText('less', lx, y + gh + 6 * U);
      for (let i = 0; i < 5; i++) {
        roundRect(ctx, lx + 70 * U + i * (cell * 0.7 + 8 * U), y + gh + 4 * U, cell * 0.7, cell * 0.7, 4 * U);
        ctx.fillStyle = i === 0 ? rgba(P.fg, 0.05) : rgba(P.accent, 0.16 + i * 0.21); ctx.fill();
      }
      ctx.fillText('more', lx + 70 * U + 5 * (cell * 0.7 + 8 * U) + 8 * U, y + gh + 6 * U);
      ctx.restore();
    }
  };

  KINDS.quote = (c, S, T) => {
    const m = M();
    const y0 = H * 0.5 - (S.top ? 0 : H * 0.06);
    const L = fitLines(S.text, (W - m.x - m.right) * 0.86, (S.size || 66) * U, 26 * U, 700, 'display', 1.24);
    const n = L.lines.length;
    // the mark sits above the measured block, whatever the block height is
    const markSize = (isTall ? 220 : 300) * U;
    const top = y0 - (n * L.size * L.lineHeight) / 2;
    ctx.save();
    ctx.globalAlpha = 0.45 * ease('outCubic', seg(T, 0.05, 0.4));
    ctx.font = font(900, markSize, 'display'); ctx.fillStyle = P.accent; ctx.textBaseline = 'top';
    ctx.fillText('“', m.x - 14 * U, top - markSize * 0.62);
    ctx.restore();
    L.lines.forEach((line, i) => {
      const p = ease('outExpo', stagger(T, i, 0.14, 0.6));
      const ly = y0 - (n * L.size * L.lineHeight) / 2 + i * L.size * L.lineHeight;
      ctx.save();
      ctx.beginPath(); ctx.rect(0, ly - L.size * 0.4, W, L.size * L.lineHeight * (p + 0.45)); ctx.clip();
      drawLines({lines: [line], size: L.size, lineHeight: L.lineHeight}, m.x, ly + (1 - p) * L.size * 0.45, P.fg, {weight: 700, fam: 'display'});
      ctx.restore();
    });
    const ay = y0 + (n * L.size * L.lineHeight) / 2 + 34 * U;
    const ap = ease('outCubic', seg(T, 0.5 + n * 0.1, 0.9 + n * 0.1));
    ctx.save(); ctx.globalAlpha = ap;
    ctx.fillStyle = P.accent; ctx.fillRect(m.x, ay + 10 * U, 54 * U * ease('outExpo', seg(T, 0.55, 0.9)), 4 * U);
    ctx.font = font(600, 24 * U, 'inter'); ctx.fillStyle = P.muted; ctx.textBaseline = 'top';
    ctx.letterSpacing = `${3 * U}px`;
    ctx.fillText(String(S.attribution || '').toUpperCase(), m.x, ay + 34 * U);
    ctx.letterSpacing = '0px';
    ctx.restore();
  };

  KINDS.stack = (c, S, T) => {
    const m = M();
    let y = m.top;
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += 42 * U; }
    if (S.headline) {
      const L = layout(S.headline, W - m.x - m.right, 800, (S.size || 62) * U, 'display', 1.05);
      revealLines(L, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += L.height + (isTall ? 60 * U : 46 * U);
    }
    if (S.sub) {
      const L = layout(S.sub, W * 0.62, 400, 26 * U, 'inter', 1.3);
      revealLines(L, m.x, y, seg(T, 0.2, 0.6), P.muted, {weight: 400, fam: 'inter'});
      y += L.height + 34 * U;
    }
    const items = S.items || [];
    const size = 30 * U, padX = 24 * U, padY = 14 * U, gap = 18 * U;
    ctx.font = font(500, size, 'mono');
    let x = m.x, rowH = size * 1.5 + padY * 2;
    items.forEach((it, i) => {
      const str = typeof it === 'string' ? it : it.name;
      const w = ctx.measureText(str).width + padX * 2;
      if (x + w > W - m.right && x > m.x) { x = m.x; y += rowH + gap; }
      const p = ease('outBack', stagger(T, i, 0.07, 0.5));
      const hot = (typeof it === 'object' && it.hot) || S.highlight === i;
      const float = Math.sin((T + i * 0.4) * 1.6) * 4 * U;
      ctx.save();
      ctx.globalAlpha = clamp(seg(T, 0.1 + i * 0.07, 0.3 + i * 0.07));
      ctx.translate(x + w / 2, y + rowH / 2 + float * p);
      ctx.scale(lerp(0.9, 1, p), lerp(0.9, 1, p));
      ctx.translate(-(x + w / 2), -(y + rowH / 2));
      roundRect(ctx, x, y, w, rowH, rowH / 2);
      ctx.fillStyle = hot ? rgba(P.accent, 0.16) : rgba(P.fg, 0.05); ctx.fill();
      ctx.strokeStyle = hot ? rgba(P.accent, 0.6) : rgba(P.fg, 0.12); ctx.lineWidth = Math.max(1, 1.4 * U); ctx.stroke();
      ctx.font = font(hot ? 700 : 500, size, 'mono'); ctx.fillStyle = hot ? P.accent : P.fg;
      ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
      ctx.fillText(str, x + padX, y + rowH / 2 + 1);
      if (typeof it === 'object' && it.note) {
        ctx.font = font(500, 18 * U, 'mono'); ctx.fillStyle = P.muted; ctx.textAlign = 'right';
        ctx.fillText(it.note, x + w - padX * 0.6, y + rowH / 2 + 1);
      }
      ctx.restore();
      x += w + gap;
    });
  };

  KINDS.image = (c, S, T) => {
    const m = M();
    const img = S._img;
    let y = m.top;
    if (S.kicker) { kicker(S.kicker, m.x, y, seg(T, 0.05, 0.3)); y += 42 * U; }
    if (S.headline) {
      const L = layout(S.headline, W - m.x - m.right, 800, (S.size || 58) * U, 'display', 1.05);
      revealLines(L, m.x, y, seg(T, 0.08, 0.5), P.fg, {weight: 800, fam: 'display'});
      y += L.height + 34 * U;
    }
    const capH = S.caption ? 56 * U : 0;
    const availH = H - m.bottom - y - capH;
    const iw = W - m.x - m.right;
    const ih = Math.min(availH, iw * (S.ratio || 0.58));
    const p = ease('outExpo', seg(T, 0.1, 0.8));
    const scale = lerp(1.05, 1, p);
    ctx.save();
    ctx.globalAlpha = clamp(seg(T, 0.05, 0.5));
    if (img) {
      ctx.save();
      ctx.shadowColor = 'rgba(0,0,0,0.5)'; ctx.shadowBlur = 40 * U; ctx.shadowOffsetY = 16 * U;
      roundRect(ctx, m.x, y, iw, ih, 20 * U); ctx.fillStyle = rgba(P.fg, 0.06); ctx.fill();
      ctx.restore();
      ctx.save();
      roundRect(ctx, m.x, y, iw, ih, 20 * U); ctx.clip();
      const r = Math.max(iw / img.width, ih / img.height) * scale;
      const dw = img.width * r, dh = img.height * r;
      ctx.drawImage(img, m.x + (iw - dw) / 2, y + (ih - dh) / 2, dw, dh);
      ctx.restore();
      roundRect(ctx, m.x, y, iw, ih, 20 * U); ctx.strokeStyle = rgba(P.fg, 0.14); ctx.lineWidth = Math.max(1, 1.5 * U); ctx.stroke();
    }
    ctx.restore();
    if (S.caption) {
      const L = layout(S.caption, iw, 500, 24 * U, 'inter', 1.3);
      revealLines(L, m.x, y + ih + 20 * U, seg(T, 0.5, 0.9), P.muted, {weight: 500, fam: 'inter'});
    }
  };

  KINDS.outro = (c, S, T) => {
    const m = M();
    const cx = W / 2;
    const y0 = H * 0.5 - (S.center === false ? H * 0.22 : 0);
    const L = fitLines(S.headline || spec.repo, W - 2 * m.x, (S.size || 96) * U, 34 * U, 800, 'display', 1.04);
    const p = ease('outExpo', seg(T, 0.05, 0.6));
    drawLines(L, cx, y0 - L.height / 2 - (S.sub ? 0 : 0), P.fg, {align: 'center', weight: 800, fam: 'display', alpha: clamp(seg(T, 0.02, 0.4)), shadow: S.glow ? P.accent : 0});
    if (S.sub) {
      const sl = layout(S.sub, W * 0.66, 400, 28 * U, 'inter', 1.35);
      drawLines(sl, cx, y0 + L.height / 2 + 22 * U, P.muted, {align: 'center', weight: 400, fam: 'inter', alpha: clamp(seg(T, 0.2, 0.6))});
    }
    if (S.url) {
      const cp = ease('outBack', seg(T, 0.3, 0.7));
      ctx.save(); ctx.globalAlpha = clamp(seg(T, 0.28, 0.5));
      chip(S.url, cx, y0 + L.height / 2 + (S.sub ? 96 * U : 44 * U), {size: 28 * U, color: P.accent, border: rgba(P.accent, 0.45), bg: rgba(P.accent, 0.1), fam: 'mono', align: 'center'});
      ctx.restore();
    }
    if (S.cta) {
      const pulse = 0.5 + 0.5 * Math.sin(T * 3.2);
      ctx.save();
      ctx.globalAlpha = clamp(seg(T, 0.45, 0.75));
      const cy = H - m.bottom - 40 * U;
      ctx.font = font(600, 30 * U, 'inter');
      const tw = ctx.measureText(S.cta).width;
      ctx.shadowColor = rgba(P.accent, 0.25 + 0.25 * pulse); ctx.shadowBlur = 40 * U;
      roundRect(ctx, cx - tw / 2 - 40 * U, cy - 42 * U, tw + 80 * U, 84 * U, 42 * U);
      ctx.fillStyle = rgba(P.accent, 0.14 + 0.08 * pulse); ctx.fill();
      ctx.strokeStyle = rgba(P.accent, 0.5 + 0.3 * pulse); ctx.lineWidth = 2 * U; ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.fillStyle = P.accent; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(S.cta, cx, cy + 1);
      ctx.restore();
    }
  };

  /* ------------------------------------------------------------- compositing */
  function sceneAt(t) {
    let k = 0;
    while (k + 1 < scenes.length && scenes[k + 1]._start <= t) k++;
    return k;
  }

  function drawSceneInto(c, S, T, alpha, t) {
    const fn = KINDS[S.kind];
    c.save();
    if (alpha < 1) c.globalAlpha = alpha;
    if (!fn) { c.fillStyle = P.fg; c.font = font(600, 40); c.fillText(`unknown scene: ${S.kind}`, M().x, M().top); c.restore(); return; }
    fn(c, S, T, t);
    c.restore();
  }

  function drawFrame(t, frame, c) {
    c.save();
    drawBackground(t, frame);
    const k = sceneAt(t);
    const S = scenes[k];
    const local = t - S._start;
    const dur = transDur(S);
    if (k > 0 && dur > 0 && local < dur) {
      const p = ease('inOutCubic', local / dur);
      const kind = transKind(S);
      const prev = scenes[k - 1];
      const pT = t - prev._start;
      if (kind === 'push') {
        drawSceneInto(c, prev, pT, 1, t);
        c.save(); c.translate((1 - p) * W * (S.direction === 'left' ? -1 : 1), 0);
        drawSceneInto(c, S, local, 1, t); c.restore();
      } else if (kind === 'zoom') {
        drawSceneInto(c, prev, pT, 1, t);
        c.save(); c.translate(W / 2, H / 2); c.scale(lerp(1.14, 1, p), lerp(1.14, 1, p)); c.translate(-W / 2, -H / 2);
        drawSceneInto(c, S, local, 1, t); c.restore();
      } else if (kind === 'wipe') {
        drawSceneInto(c, prev, pT, 1, t);
        c.save(); c.beginPath(); c.rect(0, 0, W * p, H); c.clip();
        drawSceneInto(c, S, local, 1, t); c.restore();
      } else {
        drawSceneInto(c, prev, pT, 1 - p, t);
        drawSceneInto(c, S, local, p, t);
      }
    } else {
      drawSceneInto(c, S, local, 1, t);
    }
    if (S._noFooter !== true && spec.footer !== false) footer(S, local);
    drawGrainVignette(frame, t);
    c.restore();
  }

  /* ------------------------------------------------------------------ audio */
  const A = {ctx: null, ready: false};
  const midi = m => 440 * Math.pow(2, (m - 69) / 12);
  const STYLES = {
    drift: {bpm: 84, root: 45, prog: [[0, 'm'], [8, 'M'], [3, 'M'], [10, 'M']], drums: false, arp: 'bell', pad: 0.5, bass: 'soft', hat: false},
    launch: {bpm: 112, root: 45, prog: [[0, 'm'], [8, 'M'], [3, 'M'], [10, 'M']], drums: true, arp: 'pluck', pad: 0.28, bass: 'saw', hat: true, kick: 'four'},
    pulse: {bpm: 100, root: 45, prog: [[0, 'm'], [5, 'm'], [8, 'M'], [7, 'M']], drums: true, arp: 'pluck', pad: 0.2, bass: 'square', hat: true, kick: 'four'},
    lofi: {bpm: 82, root: 45, prog: [[0, 'm7'], [8, 'M7'], [3, 'M7'], [10, 'M7']], drums: true, arp: 'bell', pad: 0.34, bass: 'soft', hat: true, kick: 'sparse', vinyl: true},
    epic: {bpm: 96, root: 43, prog: [[0, 'm'], [10, 'M'], [8, 'M'], [5, 'M']], drums: true, arp: 'saw', pad: 0.55, bass: 'saw', hat: true, kick: 'epic'},
    minimal: {bpm: 92, root: 48, prog: [[0, 'm'], [3, 'M'], [8, 'M'], [10, 'M']], drums: false, arp: 'bell', pad: 0.3, bass: 'sub', hat: false},
  };
  const CHORDS = {m: [0, 3, 7, 12], M: [0, 4, 7, 12], m7: [0, 3, 7, 10, 14], M7: [0, 4, 7, 11, 14]};
  const NOTE = n => midi(n);

  function makeNoise(ctx, seconds = 2) {
    const buf = ctx.createBuffer(1, Math.ceil(ctx.sampleRate * seconds), ctx.sampleRate);
    const d = buf.getChannelData(0);
    const r = mulberry(4242);
    for (let i = 0; i < d.length; i++) d[i] = r() * 2 - 1;
    return buf;
  }
  let NOISE = null;

  const fin = (v, d = 0) => (Number.isFinite(v) ? v : d);
  function env(g, t, a, d, peak, sustain = 0, dur = 0) {
    t = fin(t); a = fin(a, 0.005); d = fin(d, 0.1); peak = fin(peak, 0);
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(Math.max(0.0002, peak), t + a);
    if (sustain > 0 && dur > 0) {
      g.gain.setValueAtTime(Math.max(0.0002, peak), t + a + sustain);
      g.gain.exponentialRampToValueAtTime(0.0001, t + a + sustain + d);
    } else {
      g.gain.exponentialRampToValueAtTime(0.0001, t + a + d);
    }
  }

  function tone(dest, {type = 'sine', freq, t, dur, gain = 0.2, attack = 0.005, cutoff = 0, q = 0.7, pan = 0, detune = 0, glide = 0}) {
    const ctx = A.ctx;
    t = fin(t); freq = fin(freq, 220); dur = fin(dur, 0.1);
    const o = ctx.createOscillator();
    o.type = type; o.frequency.setValueAtTime(freq, t);
    if (glide) o.frequency.exponentialRampToValueAtTime(Math.max(20, freq * glide), t + dur);
    if (detune) o.detune.value = detune;
    const g = ctx.createGain();
    env(g, t, attack, dur, gain);
    let node = o;
    if (cutoff) {
      const f = ctx.createBiquadFilter(); f.type = 'lowpass'; f.frequency.value = cutoff; f.Q.value = q;
      o.connect(f); node = f;
    }
    node.connect(g);
    const p = ctx.createStereoPanner ? ctx.createStereoPanner() : null;
    if (p) { p.pan.value = pan; g.connect(p); p.connect(dest); } else g.connect(dest);
    o.start(t); o.stop(t + dur + attack + 0.05);
  }

  function noise(dest, {t, dur, gain = 0.2, type = 'bandpass', freq = 2000, q = 1, sweep = 0, pan = 0, attack = 0.002}) {
    const ctx = A.ctx;
    t = fin(t); dur = fin(dur, 0.1); freq = fin(freq, 1000);
    const s = ctx.createBufferSource(); s.buffer = NOISE; s.loop = true;
    const f = ctx.createBiquadFilter(); f.type = type; f.frequency.setValueAtTime(freq, t); f.Q.value = q;
    if (sweep) f.frequency.exponentialRampToValueAtTime(Math.max(60, freq * sweep), t + dur);
    const g = ctx.createGain(); env(g, t, attack, dur, gain);
    s.connect(f); f.connect(g);
    const p = ctx.createStereoPanner ? ctx.createStereoPanner() : null;
    if (p) { p.pan.value = pan; g.connect(p); p.connect(dest); } else g.connect(dest);
    s.start(t); s.stop(t + dur + attack + 0.1);
  }

  const kick = (dest, t, gain = 0.9) => { tone(dest, {type: 'sine', freq: 150, t, dur: 0.34, gain, glide: 0.22, attack: 0.002}); noise(dest, {t, dur: 0.03, gain: gain * 0.25, type: 'highpass', freq: 1200}); };
  const snare = (dest, t, gain = 0.35) => { noise(dest, {t, dur: 0.16, gain, type: 'bandpass', freq: 1800, q: 0.8}); tone(dest, {type: 'triangle', freq: 190, t, dur: 0.1, gain: gain * 0.5}); };
  const hat = (dest, t, gain = 0.12) => noise(dest, {t, dur: 0.05, gain, type: 'highpass', freq: 7000});
  const whoosh = (dest, t, gain = 0.3, dur = 0.5) => noise(dest, {t, dur, gain, type: 'bandpass', freq: 400, q: 0.7, sweep: 12, attack: dur * 0.35});
  const impact = (dest, t, gain = 0.8) => { tone(dest, {type: 'sine', freq: 110, t, dur: 0.8, gain, glide: 0.3}); noise(dest, {t, dur: 0.5, gain: gain * 0.3, type: 'lowpass', freq: 1800}); };
  const pop = (dest, t, gain = 0.25, f = 780) => tone(dest, {type: 'sine', freq: f, t, dur: 0.09, gain, glide: 1.6});
  const click = (dest, t, gain = 0.14) => { noise(dest, {t, dur: 0.03, gain, type: 'highpass', freq: 2600}); tone(dest, {type: 'square', freq: 1500, t, dur: 0.02, gain: gain * 0.4}); };
  const chime = (dest, t, notes, gain = 0.2) => notes.forEach((n, i) => tone(dest, {type: 'sine', freq: NOTE(n), t: t + i * 0.06, dur: 0.7, gain, attack: 0.01, pan: (i - 1) * 0.3}));

  function buildMusic(dest, dur) {
    const style = (spec.music && spec.music.style) || 'launch';
    const cfg = Object.assign({}, STYLES[style] || STYLES.launch);
    if (spec.music && spec.music.bpm) cfg.bpm = spec.music.bpm;
    if (spec.music && spec.music.root != null) cfg.root = spec.music.root;
    const bpm = cfg.bpm, spb = 60 / bpm, bar = spb * 4;
    const r = mulberry((spec.music && spec.music.seed) || SEED);
    const bars = Math.ceil((dur + 1) / bar);
    const root = cfg.root;
    for (let b = 0; b < bars; b++) {
      const t0 = b * bar, [deg, type] = cfg.prog[b % cfg.prog.length];
      const chord = CHORDS[type] || CHORDS.m;
      const bassMidi = root + deg - 12;
      // pad
      chord.forEach((iv, i) => {
        for (const det of [-6, 6]) {
          tone(dest, {type: 'sawtooth', freq: NOTE(root + 12 + deg + iv), t: t0, dur: bar * 0.98, gain: cfg.pad * 0.045, attack: bar * 0.25, cutoff: 900, detune: det, pan: i / chord.length - 0.5});
        }
      });
      // bass
      if (cfg.bass === 'sub' || cfg.bass === 'soft') {
        [0, 1.5, 2.5, 3.5].forEach((bt, i) => tone(dest, {type: 'sine', freq: NOTE(bassMidi), t: t0 + bt * spb, dur: spb * 0.9, gain: 0.34, attack: 0.01}));
      } else {
        for (let i = 0; i < 8; i++) {
          if (i % 2 === 1 && r() < 0.25) continue;
          tone(dest, {type: cfg.bass === 'square' ? 'square' : 'sawtooth', freq: NOTE(bassMidi), t: t0 + i * spb / 2, dur: spb * 0.42, gain: 0.2, cutoff: 420, q: 3});
        }
      }
      // arp / melody
      const arpNotes = chord.map(iv => root + 24 + deg + iv);
      for (let i = 0; i < 8; i++) {
        if (r() < 0.18) continue;
        const n = arpNotes[(i + b) % arpNotes.length];
        const t = t0 + i * spb / 2;
        if (cfg.arp === 'bell') tone(dest, {type: 'sine', freq: NOTE(n), t, dur: 0.5, gain: 0.1, attack: 0.005, pan: -0.4 + r() * 0.8});
        else tone(dest, {type: 'sawtooth', freq: NOTE(n), t, dur: spb * 0.3, gain: 0.08, cutoff: 2200, q: 2, pan: -0.3 + r() * 0.6});
      }
      // drums
      if (cfg.drums) {
        if (cfg.kick === 'four') for (let i = 0; i < 4; i++) kick(dest, t0 + i * spb, 0.75);
        else if (cfg.kick === 'sparse') { kick(dest, t0, 0.6); kick(dest, t0 + 2.5 * spb, 0.5); }
        else { kick(dest, t0, 0.8); kick(dest, t0 + 2 * spb, 0.6); kick(dest, t0 + 3.5 * spb, 0.55); }
        snare(dest, t0 + spb, 0.26); snare(dest, t0 + 3 * spb, 0.3);
        if (cfg.hat) for (let i = 0; i < 8; i++) if (i % 2 === 1 || r() < 0.5) hat(dest, t0 + i * spb / 2, 0.05 + r() * 0.05);
        if (cfg.kick === 'epic') { kick(dest, t0 + 2.75 * spb, 0.5); kick(dest, t0 + 3.75 * spb, 0.45); }
      }
    }
    if (cfg.vinyl) noise(dest, {t: 0, dur: dur, gain: 0.02, type: 'highpass', freq: 3000, attack: 0.5});
    // riser into the last second
    const rt = Math.max(0, dur - 1.3);
    noise(dest, {t: rt, dur: 1.2, gain: 0.12, type: 'bandpass', freq: 300, q: 0.6, sweep: 9, attack: 1.0});
  }

  function buildSfx(dest) {
    const cues = [];
    scenes.forEach((S, i) => {
      const t = S._start;
      const kind = S.kind;
      if (i === 0) cues.push({type: S.sfx || 'impact', t: 0.05, gain: 0.7});
      else {
        const tr = transDur(S);
        if (transKind(S) === 'dissolve' && tr <= 0) cues.push({type: S.sfx || 'whoosh', t: Math.max(0.02, t - 0.22), gain: 0.22});
        else cues.push({type: S.sfx || (kind === 'stat' ? 'pop' : 'click'), t: t + 0.02, gain: 0.2});
        if (kind === 'features' || kind === 'stack') for (let k = 1; k < 3; k++) cues.push({type: 'click', t: t + 0.12 + k * 0.11, gain: 0.1});
        if (kind === 'stat') cues.push({type: 'chime', t: t + 0.85, gain: 0.14, notes: [rootNote() + 24, rootNote() + 28]});
      }
    });
    cues.push({type: 'impact', t: Math.max(0, DURATION - 0.55), gain: 0.5});
    for (const cue of cues) {
      if (cue.t > DURATION) continue;
      switch (cue.type) {
        case 'whoosh': whoosh(dest, cue.t, cue.gain); break;
        case 'impact': impact(dest, cue.t, cue.gain); break;
        case 'pop': pop(dest, cue.t, cue.gain); break;
        case 'click': click(dest, cue.t, cue.gain); break;
        case 'chime': chime(dest, cue.t, cue.notes, cue.gain); break;
        case 'riser': noise(dest, {t: cue.t, dur: 1.2, gain: cue.gain, type: 'bandpass', freq: 300, q: 0.6, sweep: 9, attack: 1.0}); break;
        default: click(dest, cue.t, cue.gain);
      }
    }
  }
  function rootNote() { const s = (spec.music && spec.music.root) || 45; return s; }

  function encodeWav(buf) {
    const chans = buf.numberOfChannels, len = buf.length, sr = buf.sampleRate;
    const data = [];
    for (let c = 0; c < chans; c++) data.push(buf.getChannelData(c));
    // Aim for the -14 LUFS that social platforms normalise to, then soft-clip whatever
    // the peak ceiling did not allow. tanh keeps |sample| < 1, so this cannot clip hard.
    // Loudness is calibrated against plain RMS, which for this material sits ~3.4 dB
    // under K-weighted LUFS; the loop below converges on the target and backs off the
    // drive if the result would exceed the peak ceiling.
    const targetDb = (spec.audioTarget == null ? -14 : spec.audioTarget) - 3.4;
    const ceiling = spec.audioCeiling == null ? 0.78 : spec.audioCeiling;
    const fade = Math.min(len, Math.floor(sr * 0.25));
    const envelope = new Float32Array(len);
    for (let i = 0; i < len; i++) {
      let v = 1;
      if (i < 400) v = i / 400;
      if (i > len - fade) v *= Math.max(0, (len - i) / fade);
      envelope[i] = v;
    }
    const out = new Float32Array(len * chans);
    const tanh = Math.tanh;
    let gain = 1, drive = 1;
    for (let iter = 0; iter < 4; iter++) {
      let peak = 0, sumSq = 0, n = 0;
      for (let i = 0; i < len; i++) {
        const env = envelope[i];
        for (let c = 0; c < chans; c++) {
          let s = data[c][i] * gain * env;
          if (drive > 1) s = tanh(s * drive) / tanh(drive);
          out[i * chans + c] = s;
          const a = s < 0 ? -s : s;
          if (a > peak) peak = a;
          sumSq += s * s; n++;
        }
      }
      const rms = Math.sqrt(sumSq / Math.max(1, n));
      const err = targetDb - 20 * Math.log10(rms + 1e-9);
      const over = peak - ceiling;
      if (Math.abs(err) < 0.25 && over <= 0) break;
      if (over > 0) {
        // keep the ceiling: trade loudness for drive (soft saturation)
        drive = Math.min(2.4, drive + Math.max(0.06, over * 2.2));
        gain *= Math.pow(10, (targetDb - 20 * Math.log10(rms + 1e-9)) / 20);
      } else {
        gain *= Math.pow(10, err / 20);
      }
      if (!Number.isFinite(gain) || gain <= 0) { gain = 1; break; }
      gain = Math.min(gain, 12);
    }
    const bytes = new Uint8Array(44 + len * chans * 2);
    const dv = new DataView(bytes.buffer);
    const str = (o, s) => { for (let i = 0; i < s.length; i++) bytes[o + i] = s.charCodeAt(i); };
    str(0, 'RIFF'); dv.setUint32(4, 36 + len * chans * 2, true); str(8, 'WAVE'); str(12, 'fmt ');
    dv.setUint32(16, 16, true); dv.setUint16(20, 1, true); dv.setUint16(22, chans, true);
    dv.setUint32(24, sr, true); dv.setUint32(28, sr * chans * 2, true); dv.setUint16(32, chans * 2, true);
    dv.setUint16(34, 16, true); str(36, 'data'); dv.setUint32(40, len * chans * 2, true);
    let o = 44;
    for (let i = 0; i < len * chans; i++) {
      let s = out[i];
      s = s > 1 ? 1 : s < -1 ? -1 : s;
      dv.setInt16(o, s * 32767, true); o += 2;
    }
    let bin = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return btoa(bin);
  }

  async function renderScore() {
    const sr = 48000;
    const dur = DURATION + 0.8;
    A.ctx = new OfflineAudioContext(2, Math.ceil(sr * dur), sr);
    NOISE = makeNoise(A.ctx, 2);
    // glue compressor -> brickwall-ish limiter: social platforms normalise to -14 LUFS,
    // so a squashed mix that peaks at -1 dBFS lands in the right place.
    const comp = A.ctx.createDynamicsCompressor();
    comp.threshold.value = -20; comp.knee.value = 8; comp.ratio.value = 6; comp.attack.value = 0.003; comp.release.value = 0.12;
    const limiter = A.ctx.createDynamicsCompressor();
    limiter.threshold.value = -1.5; limiter.knee.value = 0; limiter.ratio.value = 20; limiter.attack.value = 0.001; limiter.release.value = 0.05;
    const master = A.ctx.createGain(); master.gain.value = 0.95;
    comp.connect(limiter); limiter.connect(master); master.connect(A.ctx.destination);
    const musicBus = A.ctx.createGain(); musicBus.gain.value = spec.music && spec.music.gain != null ? spec.music.gain : 0.75; musicBus.connect(comp);
    const sfxBus = A.ctx.createGain(); sfxBus.gain.value = spec.sfx === false ? 0 : (spec.sfxGain == null ? 0.55 : spec.sfxGain); sfxBus.connect(comp);
    const voiceBus = A.ctx.createGain(); voiceBus.gain.value = spec.voiceGain == null ? 1 : spec.voiceGain; voiceBus.connect(comp);
    if (!spec.music || spec.music.style !== 'none') buildMusic(musicBus, DURATION);
    if (spec.sfx !== false) buildSfx(sfxBus);
    const voice = window.__VOICE || [];
    for (const v of voice) {
      try {
        const bin = atob(v.b64);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        const buf = await A.ctx.decodeAudioData(u8.buffer);
        const src = A.ctx.createBufferSource(); src.buffer = buf;
        const g = A.ctx.createGain(); g.gain.value = v.gain == null ? 1 : v.gain;
        src.connect(g); g.connect(voiceBus);
        src.start(Math.max(0, v.t || 0));
      } catch (e) { /* a broken voice line must not kill the render */ }
    }
    const rendered = await A.ctx.startRendering();
    return encodeWav(rendered);
  }

  /* --------------------------------------------------------------- previews */
  function drawScaled(i, target, scale) {
    // Draw at full size into the main canvas, then downscale: every scene helper
    // draws through the module-level context, so there is no second code path.
    drawFrame(i / FPS, i, ctx);
    target.width = Math.max(1, Math.round(W * scale));
    target.height = Math.max(1, Math.round(H * scale));
    target.getContext('2d').drawImage(canvas, 0, 0, target.width, target.height);
  }

  window.__poster = () => {
    const cands = [];
    const step = Math.max(1, Math.floor(NFRAMES / 60));
    for (let i = Math.floor(NFRAMES * 0.04); i < NFRAMES * 0.94; i += step) cands.push(i);
    const tmp = document.createElement('canvas'), sm = document.createElement('canvas');
    const sctx2 = sm.getContext('2d', {willReadFrequently: true});
    let best = {score: -1, index: Math.floor(NFRAMES * 0.3)};
    for (const i of cands) {
      drawScaled(i, tmp, 0.14);
      sm.width = 84; sm.height = Math.round(84 * H / W);
      sctx2.drawImage(tmp, 0, 0, sm.width, sm.height);
      const d = sctx2.getImageData(0, 0, sm.width, sm.height).data;
      let sum = 0, sum2 = 0, sat = 0, edge = 0, n = 0;
      const lum = new Float32Array(sm.width * sm.height);
      for (let p = 0, q = 0; p < d.length; p += 4, q++) {
        const l = (0.299 * d[p] + 0.587 * d[p + 1] + 0.114 * d[p + 2]) / 255;
        lum[q] = l; sum += l; sum2 += l * l; n++;
        const mx = Math.max(d[p], d[p + 1], d[p + 2]), mn = Math.min(d[p], d[p + 1], d[p + 2]);
        sat += mx > 0 ? (mx - mn) / mx : 0;
      }
      for (let y = 1; y < sm.height - 1; y++) for (let x = 1; x < sm.width - 1; x++) {
        const q = y * sm.width + x;
        edge += Math.abs(lum[q] - lum[q - 1]) + Math.abs(lum[q] - lum[q - sm.width]);
      }
      const mean = sum / n;
      const std = Math.sqrt(Math.max(0, sum2 / n - mean * mean));
      const score = std * 2.2 + (sat / n) * 0.7 + (edge / (n * 2)) * 1.1;
      if (score > best.score) best = {score, index: i};
    }
    const tmp2 = document.createElement('canvas');
    drawScaled(best.index, tmp2, 1);
    return {index: best.index, score: best.score, url: tmp2.toDataURL('image/png')};
  };

  function tile(indices, cols, cellW) {
    const cellH = Math.round(cellW * H / W);
    const rows = Math.ceil(indices.length / cols);
    sheet.width = cellW * cols; sheet.height = cellH * rows;
    const tmp = document.createElement('canvas');
    indices.forEach((i, k) => {
      drawScaled(i, tmp, cellW / W);
      sctx.drawImage(tmp, (k % cols) * cellW, Math.floor(k / cols) * cellH, cellW, cellH);
    });
    return sheet.toDataURL('image/jpeg', 0.82);
  }
  window.__contact = (cols = 5, rows = 4) => {
    const step = NFRAMES / (cols * rows);
    return tile(Array.from({length: cols * rows}, (_, k) => Math.floor(k * step)), cols, 384);
  };
  window.__strip = (start, count) => {
    count = Math.min(count, 12);
    return tile(Array.from({length: count}, (_, k) => Math.min(NFRAMES - 1, start + k)), Math.min(count, 6), 320);
  };
  window.__scenes = () => scenes.map(s => ({kind: s.kind, start: s._start, end: s._end, headline: s.headline || s.text || s.repo || null}));

  /* ---------------------------------------------------------------- exports */
  window.__NDRAW = NFRAMES;
  window.__fps = FPS;
  window.__size = {w: W, h: H};
  window.__duration = DURATION;
  window.__frame = (i, mime = 'image/png', q = 0.95) => {
    const idx = Math.max(0, Math.min(NFRAMES - 1, Math.round(i)));
    drawFrame(idx / FPS, idx, ctx);
    return mime === 'image/png' ? canvas.toDataURL('image/png') : canvas.toDataURL(mime, q);
  };
  window.__wav = () => renderScore();
  window.__loadImage = (src) => new Promise(res => {
    const im = new Image();
    im.onload = () => {
      scenes.forEach(s => { if (s.image && s._imgSrc === src) s._img = im; });
      res(true);
    };
    im.onerror = () => res(false);
    im.src = src;
  });

  // resolve any image assets declared in the spec
  (async () => {
    try {
      const loads = [];
      for (const S of scenes) {
        if (S.image) {
          S._imgSrc = S.image;
          loads.push(new Promise(res => {
            const im = new Image();
            im.onload = () => { S._img = im; res(); };
            im.onerror = () => { window.__error = `image failed to load: ${String(S.image).slice(0, 80)}`; res(); };
            im.src = S.image;
          }));
        }
      }
      if (loads.length) await Promise.all(loads);
      const faces = window.__FONT_FACES || [];
      await Promise.all(faces.map(f => {
        const ff = new FontFace(f.family, `url(${f.url})`, {weight: String(f.weight), style: f.style});
        document.fonts.add(ff);
        return ff.load().catch(() => {});
      }));
      await document.fonts.ready;
      window.__ready = true;
    } catch (e) {
      window.__error = String(e && e.message || e);
    }
  })();
})();
