/* PacketLens — interface : chargement, chronologie, alertes, carte, tableaux. */
{
  const $ = s => document.querySelector(s);
  // Tout ce qui vient de la capture est échappé : un fichier piégé ne peut pas injecter de HTML.
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const SEVC = { crit: '#e8452c', haute: '#f39a3d', moy: '#f7e463', info: '#4fc1c6' };
  const SEVL = { crit: 'Critique', haute: 'Élevée', moy: 'Moyenne', info: 'Info' };
  const ROLEC = { attaquant: '#e8452c', compromis: '#e8452c', cible: '#f7e463', 'exposé': '#f7e463' };
  const ROLEL = { attaquant: 'Attaquant', compromis: 'Machine compromise', cible: 'Cible', 'exposé': 'Identifiants exposés' };
  const PCOL = ['#3b4fd8', '#4fc1c6', '#8c9bff', '#f7e463', '#e86fb0', '#f39a3d', '#6fd3a8', '#a3acd3'];
  const nf = new Intl.NumberFormat('fr-FR');
  const inFrame = (() => { try { return window.self !== window.top; } catch (e) { return true; } })();

  let A = null, fileName = '', limit = 300, sel = null, onlyAlert = null, sample = null;
  let nodes = [], nodeEdges = [];

  const fmtBytes = b => b < 1024 ? b + ' o' : b < 1048576 ? (b / 1024).toFixed(1).replace('.', ',') + ' Ko' : (b / 1048576).toFixed(1).replace('.', ',') + ' Mo';
  const rel = t => { const s = t - A.t0, m = Math.floor(s / 60); return m ? `${m} min ${String(Math.floor(s % 60)).padStart(2, '0')} s` : s.toFixed(1).replace('.', ',') + ' s'; };
  const clock = t => new Date(t * 1000).toLocaleTimeString('fr-FR');
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('on'), 3200); }

  function load(buf, name) {
    try {
      const cap = PL.readCapture(buf);
      if (!cap.packets.length) throw new Error('Aucun paquet lisible dans ce fichier.');
      A = PL.analyze(cap);
      A.format = cap.format;
      fileName = name; sel = null; onlyAlert = null; limit = 300;
      $('#q').value = ''; $('#onlyBad').checked = false;
      const first = A.hosts.find(h => h.role === 'attaquant' || h.role === 'compromis') || A.hosts[0];
      sel = first ? first.ip : null;
      renderAll();
    } catch (e) { toast(e.message); }
  }

  function renderAll() {
    renderStatus(); drawTimeline(); renderAlerts(); layoutGraph(); drawGraph(); renderHost();
    drawDonut(); renderTalkers(); renderTable();
  }

  /* ---------- Résumé ---------- */
  function renderStatus() {
    const cnt = {};
    for (const a of A.alerts) cnt[a.sev] = (cnt[a.sev] || 0) + 1;
    const c = A.worst === 'none' ? 'var(--cyan)' : SEVC[A.worst];
    const verdict = A.worst === 'none' ? 'Rien de suspect détecté' : A.worst === 'crit' ? 'Attaque en cours ou réussie' : A.worst === 'haute' ? 'Activité malveillante probable' : 'Activité à surveiller';
    const kpi = [['Paquets', nf.format(A.pk.length)], ['Durée', PL.fmtDur(A.t1 - A.t0)], ['Volume', fmtBytes(A.bytes)], ['Machines', nf.format(A.hosts.length)]];
    $('#status').innerHTML = `<p class="file">Fichier <b>${esc(fileName)}</b> · format ${esc(A.format)} · début ${A.t0 ? esc(new Date(A.t0 * 1000).toLocaleString('fr-FR')) : 'inconnu'}</p>
      <div class="kpis">${kpi.map(([l, v]) => `<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join('')}
      <div class="kpi verdict" style="--c:${c}"><b>${A.alerts.length ? nf.format(A.alerts.length) + ' alerte' + (A.alerts.length > 1 ? 's' : '') : 'Aucune alerte'}</b><span>${verdict}</span>
      <div class="sevs">${['crit', 'haute', 'moy', 'info'].filter(s => cnt[s]).map(s => `<span class="pill" style="--c:${SEVC[s]}">${cnt[s]} ${SEVL[s].toLowerCase()}</span>`).join('')}</div></div></div>`;
  }

  /* ---------- Chronologie ---------- */
  function drawTimeline() {
    const fig = $('#tl'), s = $('#tlsvg');
    if (!A) return;
    const lanes = A.alerts.length;
    fig.style.height = (150 + (lanes ? 16 + lanes * 26 : 0) + 6) + 'px';
    const W = s.clientWidth, H = s.clientHeight;
    if (!W) return;
    const L = 6, R = 6, hH = 110, dur = Math.max(A.t1 - A.t0, 0.001);
    const x = t => L + (t - A.t0) / dur * (W - L - R);
    const nb = Math.max(20, Math.min(220, Math.floor(W / 5)));
    const bins = new Array(nb).fill(0), badb = new Array(nb).fill(0);
    for (const r of A.pk) {
      const b = Math.min(nb - 1, Math.floor((r.ts - A.t0) / dur * nb));
      bins[b]++;
      if (A.bad.has(r.i)) badb[b]++;
    }
    const max = Math.max(1, ...bins), sq = v => Math.sqrt(v / max), bw = (W - L - R) / nb;
    let out = '';
    for (let i = 0; i < nb; i++) {
      if (!bins[i]) continue;
      const h = Math.max(2, sq(bins[i]) * (hH - 22)), hb = h * badb[i] / bins[i];
      out += `<rect x="${(L + i * bw).toFixed(1)}" y="${(hH - h).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h.toFixed(1)}" rx="1" fill="#3b4fd8"/>`;
      if (badb[i]) out += `<rect x="${(L + i * bw).toFixed(1)}" y="${(hH - hb).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${Math.max(1.5, hb).toFixed(1)}" rx="1" fill="#f39a3d"/>`;
    }
    out += `<line x1="${L}" x2="${W - R}" y1="${hH + .5}" y2="${hH + .5}" stroke="#26346f"/>`;
    const nt = W < 520 ? 3 : 6;
    for (let k = 0; k <= nt; k++) {
      const t = A.t0 + dur * k / nt, xx = x(t);
      const anchor = k === 0 ? 'start' : k === nt ? 'end' : 'middle';
      out += `<line x1="${xx}" x2="${xx}" y1="${hH}" y2="${hH + 5}" stroke="#26346f"/><text x="${xx}" y="${hH + 22}" fill="#a3acd3" font-size="13" text-anchor="${anchor}">${k === 0 ? esc(clock(A.t0)) : '+' + esc(rel(t))}</text>`;
    }
    out += `<text x="${L}" y="14" fill="#a3acd3" font-size="13">${nf.format(max)} paquets au maximum par tranche de ${esc(PL.fmtDur(dur / nb))} (échelle en racine carrée)</text>`;
    A.alerts.forEach((a, k) => {
      const y = hH + 40 + k * 26, xs = x(a.ts), xe = Math.max(xs + 8, x(a.te));
      const label = `${a.n}. ${a.title}`, tw = label.length * 7.2;
      const right = xe + 8 + tw < W, tx = right ? xe + 8 : Math.max(L + tw, xs - 8);
      out += `<g class="lane" data-n="${a.n}" tabindex="0" role="button" aria-label="Alerte ${a.n} : ${esc(a.title)}">
        <rect x="0" y="${y - 4}" width="${W}" height="24" fill="transparent"/>
        <line x1="${L}" x2="${W - R}" y1="${y + 8}" y2="${y + 8}" stroke="#172456"/>
        <rect class="bar" x="${xs.toFixed(1)}" y="${y + 1}" width="${(xe - xs).toFixed(1)}" height="14" rx="4" fill="${SEVC[a.sev]}"/>
        <text x="${tx.toFixed(1)}" y="${y + 13}" fill="#eef0fa" font-size="13" text-anchor="${right ? 'start' : 'end'}">${esc(label)}</text>
        <title>${esc(a.title)} · ${esc(rel(a.ts))} → ${esc(rel(a.te))}</title></g>`;
    });
    s.setAttribute('viewBox', `0 0 ${W} ${H}`);
    s.innerHTML = out;
  }

  /* ---------- Alertes ---------- */
  const mitreUrl = id => 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
  function renderAlerts() {
    const el = $('#alerts');
    if (!A.alerts.length) {
      el.innerHTML = `<div class="empty"><b>Aucune alerte</b>PacketLens n'a trouvé aucun des comportements qu'il sait reconnaître : scan de ports, balayage du réseau, brute force, ARP spoofing, tunnel DNS ou identifiants envoyés en clair.</div>`;
      return;
    }
    el.innerHTML = A.alerts.map(a => `<article class="alert" id="al-${a.n}" style="--c:${SEVC[a.sev]}">
      <header><span class="n">${a.n}</span><h3>${esc(a.title)}</h3><span class="pill" style="--c:${SEVC[a.sev]}">${SEVL[a.sev]}</span></header>
      <p class="meta">${esc(clock(a.ts))} (+${esc(rel(a.ts))}) · ${esc(a.src)} → ${esc(a.dst)}</p>
      <p>${esc(a.detail)}</p>
      <p class="tip"><b>À faire :</b> ${esc(a.conseil)}</p>
      <footer><a href="${mitreUrl(a.mitre[0])}" target="_blank" rel="noopener">MITRE ATT&amp;CK ${esc(a.mitre[0])} · ${esc(a.mitre[1])}</a>
      <button type="button" data-show="${a.n}">Voir ${a.idx.length > 1 ? 'les ' + nf.format(a.idx.length) + ' paquets' : 'le paquet'}</button></footer></article>`).join('');
  }
  function focusAlert(n) {
    const el = $('#al-' + n);
    if (!el) return;
    el.scrollIntoView({ block: 'center' });
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 1400);
  }

  /* ---------- Carte des échanges (graphe à ressorts, calculé une fois) ---------- */
  function layoutGraph() {
    const top = A.hosts.filter(h => !/^(255\.|0\.0\.0\.0|224\.|ff0)/.test(h.ip)).slice(0, 40);
    const idx = new Map(top.map((h, i) => [h.ip, i]));
    nodes = top.map((h, i) => {
      const ang = i / top.length * Math.PI * 2;
      return { h, x: 0.5 + 0.35 * Math.cos(ang), y: 0.5 + 0.35 * Math.sin(ang), dx: 0, dy: 0 };
    });
    nodeEdges = A.edges.filter(e => idx.has(e.a) && idx.has(e.b) && e.a !== e.b).map(e => ({ e, s: idx.get(e.a), t: idx.get(e.b) }));
    const n = nodes.length;
    if (!n) return;
    const k = 0.9 * Math.sqrt(1 / n);
    let temp = 0.1;
    for (let it = 0; it < 350; it++) {
      for (const a of nodes) { a.dx = 0; a.dy = 0; }
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        const d = Math.max(0.01, Math.hypot(dx, dy)), f = k * k / d;
        dx /= d; dy /= d;
        a.dx += dx * f; a.dy += dy * f; b.dx -= dx * f; b.dy -= dy * f;
      }
      for (const { s, t } of nodeEdges) {
        const a = nodes[s], b = nodes[t];
        let dx = a.x - b.x, dy = a.y - b.y;
        const d = Math.max(0.01, Math.hypot(dx, dy)), f = d * d / k;
        dx /= d; dy /= d;
        a.dx -= dx * f; a.dy -= dy * f; b.dx += dx * f; b.dy += dy * f;
      }
      for (const a of nodes) {
        a.dx += (0.5 - a.x) * 0.6; a.dy += (0.5 - a.y) * 0.6;
        const d = Math.max(1e-6, Math.hypot(a.dx, a.dy)), m = Math.min(d, temp);
        a.x += a.dx / d * m; a.y += a.dy / d * m;
      }
      temp *= 0.985;
    }
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    for (const a of nodes) { x0 = Math.min(x0, a.x); x1 = Math.max(x1, a.x); y0 = Math.min(y0, a.y); y1 = Math.max(y1, a.y); }
    for (const a of nodes) { a.x = (a.x - x0) / Math.max(1e-6, x1 - x0); a.y = (a.y - y0) / Math.max(1e-6, y1 - y0); }
  }
  const nodeColor = h => ROLEC[h.role] || (h.local ? '#3b4fd8' : '#4fc1c6');
  const nodeR = h => 6 + Math.min(16, Math.log10(1 + h.bout + h.bin) * 2.2);
  function placed(W, H) {
    const px = 70, py = 34;
    return nodes.map(a => ({ a, X: px + a.x * (W - 2 * px), Y: py + a.y * (H - 2 * py - 16) }));
  }
  function drawGraph() {
    const cv = $('#graph'), W = cv.clientWidth, H = cv.clientHeight;
    if (!W || !A) return;
    const dpr = window.devicePixelRatio || 1;
    cv.width = W * dpr; cv.height = H * dpr;
    const g = cv.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, W, H);
    const P = placed(W, H);
    const hot = new Map();
    for (const a of A.alerts) for (const d of String(a.dst).split(', ')) hot.set(a.src + '|' + d.split(':')[0], a.sev);
    for (const { e, s, t } of nodeEdges) {
      const A1 = P[s], B1 = P[t];
      const sev = hot.get(e.a + '|' + e.b) || hot.get(e.b + '|' + e.a);
      const on = sel && (e.a === sel || e.b === sel);
      g.strokeStyle = sev ? SEVC[sev] : on ? 'rgba(238,240,250,.7)' : 'rgba(163,172,211,.28)';
      g.lineWidth = (sev ? 1.5 : 0.6) + Math.log10(1 + e.bytes) * 0.45;
      g.beginPath(); g.moveTo(A1.X, A1.Y); g.lineTo(B1.X, B1.Y); g.stroke();
    }
    g.font = '500 12px "Red Hat Mono", monospace';
    g.textAlign = 'center';
    for (const { a, X, Y } of P) {
      const r = nodeR(a.h);
      g.beginPath(); g.arc(X, Y, r, 0, Math.PI * 2);
      g.fillStyle = nodeColor(a.h); g.fill();
      g.lineWidth = a.h.ip === sel ? 3 : 1.5;
      g.strokeStyle = a.h.ip === sel ? '#ffffff' : 'rgba(11,20,51,.9)';
      g.stroke();
      g.fillStyle = a.h.ip === sel ? '#ffffff' : '#c9cfea';
      g.fillText(a.h.ip, X, Y + r + 14);
    }
  }
  function graphClick(ev) {
    const cv = $('#graph'), b = cv.getBoundingClientRect();
    const mx = ev.clientX - b.left, my = ev.clientY - b.top;
    let best = null, bd = Infinity;
    for (const p of placed(cv.clientWidth, cv.clientHeight)) {
      const d = Math.hypot(p.X - mx, p.Y - my);
      if (d < nodeR(p.a.h) + 10 && d < bd) { bd = d; best = p.a.h; }
    }
    if (best) { sel = best.ip; drawGraph(); renderHost(); }
  }

  function renderHost() {
    const el = $('#host'), h = A.hosts.find(x => x.ip === sel);
    if (!h) { el.innerHTML = '<p class="note">Cliquez sur une machine de la carte.</p>'; return; }
    const ports = [...h.ports].sort((a, b) => a - b);
    const role = ROLEL[h.role] || (h.local ? 'Machine du réseau local' : 'Machine sur Internet');
    el.innerHTML = `<h3>${esc(h.ip)}</h3><p class="role" style="color:${ROLEC[h.role] || 'var(--mute)'}">${esc(role)}</p>
      <dl>
        <dt>Adresse${h.macs.size > 1 ? 's' : ''} MAC</dt><dd>${h.macs.size ? [...h.macs].map(m => `<code>${esc(m)}</code>`).join(', ') + (h.macs.size > 1 ? ' <b style="color:var(--red)">· plusieurs cartes pour une IP</b>' : '') : '—'}</dd>
        <dt>Envoyé</dt><dd>${nf.format(h.out)} paquets · ${fmtBytes(h.bout)}</dd>
        <dt>Reçu</dt><dd>${nf.format(h.inn)} paquets · ${fmtBytes(h.bin)}</dd>
        <dt>Protocoles</dt><dd>${esc([...h.protos].join(', '))}</dd>
        <dt>Ports contactés</dt><dd>${ports.length ? esc(ports.slice(0, 18).join(', ')) + (ports.length > 18 ? ` et ${ports.length - 18} autres` : '') : '—'}</dd>
        <dt>Correspondants</dt><dd>${h.peers.size}</dd>
      </dl>
      <div class="links">${h.alerts.map(n => `<button type="button" data-goto="${n}">Alerte ${n}</button>`).join('')}
      <button type="button" data-filter="${esc(h.ip)}">Voir ses paquets</button></div>`;
  }

  /* ---------- Protocoles et machines actives ---------- */
  function drawDonut() {
    const s = $('#donut'), W = s.clientWidth, H = s.clientHeight;
    const total = A.pk.length;
    let rows = A.protos.slice(0, 7);
    const rest = A.protos.slice(7).reduce((t, p) => t + p[1], 0);
    if (rest) rows = rows.concat([['Autres', rest]]);
    $('#plegend').innerHTML = rows.map(([p, n], i) => `<div class="prow"><span>${esc(p)}</span><span class="meter"><i style="width:${(n / total * 100).toFixed(1)}%;--c:${PCOL[i]}"></i></span><b>${(n / total * 100).toFixed(1).replace('.', ',')} %</b></div>`).join('');
    if (!W) return;
    const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 4, r = R * 0.62;
    let a0 = -Math.PI / 2, out = '';
    rows.forEach(([, n], i) => {
      const a1 = a0 + n / total * Math.PI * 2 - (rows.length > 1 ? 0.012 : 0.0001);
      const big = a1 - a0 > Math.PI ? 1 : 0;
      const p = (rad, a) => `${(cx + rad * Math.cos(a)).toFixed(2)} ${(cy + rad * Math.sin(a)).toFixed(2)}`;
      out += `<path d="M${p(R, a0)}A${R} ${R} 0 ${big} 1 ${p(R, a1)}L${p(r, a1)}A${r} ${r} 0 ${big} 0 ${p(r, a0)}Z" fill="${PCOL[i]}"/>`;
      a0 += n / total * Math.PI * 2;
    });
    out += `<text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="#eef0fa" font-family="Red Hat Display" font-weight="800" font-size="26">${nf.format(total)}</text><text x="${cx}" y="${cy + 18}" text-anchor="middle" fill="#a3acd3" font-size="13">paquets</text>`;
    s.setAttribute('viewBox', `0 0 ${W} ${H}`);
    s.innerHTML = out;
  }
  function renderTalkers() {
    const top = A.hosts.slice(0, 8), max = Math.max(1, ...top.map(h => h.bout + h.bin));
    $('#talkers').innerHTML = top.map(h => `<button type="button" class="trow" data-host="${esc(h.ip)}"><span>${esc(h.ip)}${h.role ? `<span class="tag" style="--c:${ROLEC[h.role]}">${esc(h.role)}</span>` : ''}</span>
      <span class="meter"><i style="width:${((h.bout + h.bin) / max * 100).toFixed(1)}%;--c:${nodeColor(h)}"></i></span><b>${fmtBytes(h.bout + h.bin)}</b></button>`).join('');
  }

  /* ---------- Table des paquets ---------- */
  function rowText(r) { return r._s || (r._s = `${r.src} ${r.dst} ${r.proto} ${r.sport ?? ''} ${r.dport ?? ''} ${r.srcMac || ''} ${r.info}`.toLowerCase()); }
  function renderTable() {
    const q = $('#q').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const onlyBad = $('#onlyBad').checked;
    const set = onlyAlert ? new Set(A.alerts[onlyAlert - 1].idx) : null;
    const rows = A.pk.filter(r => (!set || set.has(r.i)) && (!onlyBad || A.bad.has(r.i)) && q.every(t => rowText(r).includes(t)));
    const shown = rows.slice(0, limit);
    $('#ptable tbody').innerHTML = shown.map(r => {
      const sev = A.bad.get(r.i);
      return `<tr${sev ? ` class="bad" style="--c:${SEVC[sev]}"` : ''}><td class="num">${r.i + 1}</td><td class="num">${(r.ts - A.t0).toFixed(3).replace('.', ',')}</td><td>${esc(r.src || r.srcMac || '')}</td><td>${esc(r.dst || r.dstMac || '')}</td><td>${esc(r.proto)}</td><td class="num">${r.len}</td><td>${esc(r.info)}</td></tr>`;
    }).join('') || '<tr><td colspan="7">Aucun paquet ne correspond au filtre.</td></tr>';
    $('#count').innerHTML = `${nf.format(shown.length)} paquets affichés sur ${nf.format(rows.length)} correspondants (${nf.format(A.pk.length)} au total)` +
      (onlyAlert ? ` <button type="button" id="clearAlert">Paquets de l'alerte ${onlyAlert} · retirer ce filtre</button>` : '');
    $('#more').hidden = rows.length <= limit;
  }

  /* ---------- Rapport JSON ---------- */
  function report() {
    return {
      outil: 'PacketLens', fichier: fileName, format: A.format, genere_le: new Date().toISOString(),
      capture: { debut: new Date(A.t0 * 1000).toISOString(), fin: new Date(A.t1 * 1000).toISOString(), paquets: A.pk.length, octets: A.bytes, machines: A.hosts.length },
      protocoles: Object.fromEntries(A.protos),
      alertes: A.alerts.map(a => ({ numero: a.n, gravite: SEVL[a.sev], type: a.type, titre: a.title, debut: new Date(a.ts * 1000).toISOString(), fin: new Date(a.te * 1000).toISOString(), source: a.src, destination: a.dst, detail: a.detail, recommandation: a.conseil, mitre: { id: a.mitre[0], nom: a.mitre[1], url: mitreUrl(a.mitre[0]) }, paquets: a.idx.map(i => i + 1) })),
      machines: A.hosts.slice(0, 50).map(h => ({ ip: h.ip, role: h.role || null, macs: [...h.macs], paquets_envoyes: h.out, paquets_recus: h.inn, octets: h.bout + h.bin, ports_contactes: [...h.ports].sort((a, b) => a - b), alertes: h.alerts }))
    };
  }

  /* ---------- Événements ---------- */
  $('#samples').innerHTML = Object.entries(PL.SAMPLES).map(([k, s]) => `<button type="button" data-sample="${k}" aria-pressed="false">${esc(s.label)}</button>`).join('');
  function loadSample(k) {
    sample = k;
    for (const b of document.querySelectorAll('[data-sample]')) b.setAttribute('aria-pressed', String(b.dataset.sample === k));
    $('#sdesc').textContent = PL.SAMPLES[k].desc;
    const u8 = PL.buildSample(k);
    load(u8.buffer, `exemple-${k}.pcap`);
  }
  function loadFile(f) {
    if (!f) return;
    if (f.size > 300 * 1048576) { toast('Fichier trop gros (plus de 300 Mo) pour être analysé dans le navigateur.'); return; }
    sample = null;
    for (const b of document.querySelectorAll('[data-sample]')) b.setAttribute('aria-pressed', 'false');
    $('#sdesc').textContent = '';
    f.arrayBuffer().then(b => load(b, f.name), () => toast('Impossible de lire ce fichier.'));
  }
  $('#file').addEventListener('change', e => { loadFile(e.target.files[0]); e.target.value = ''; });
  const drop = $('#drop');
  for (const ev of ['dragenter', 'dragover']) document.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); });
  for (const ev of ['dragleave', 'drop']) document.addEventListener(ev, e => { e.preventDefault(); if (ev === 'drop' || !e.relatedTarget) drop.classList.remove('over'); });
  document.addEventListener('drop', e => loadFile(e.dataTransfer && e.dataTransfer.files[0]));

  document.addEventListener('click', e => {
    const t = e.target.closest('button, .lane');
    if (!t) return;
    const d = t.dataset;
    if (d.sample) loadSample(d.sample);
    else if (d.show) { onlyAlert = +d.show; limit = 300; renderTable(); $('#packets').scrollIntoView(); }
    else if (d.n) focusAlert(+d.n);
    else if (d.goto) focusAlert(+d.goto);
    else if (d.filter) { $('#q').value = d.filter; onlyAlert = null; limit = 300; renderTable(); $('#packets').scrollIntoView(); }
    else if (d.host) { sel = d.host; drawGraph(); renderHost(); $('#gfig').scrollIntoView({ block: 'center' }); }
    else if (t.id === 'clearAlert') { onlyAlert = null; renderTable(); }
  });
  $('#tlsvg').addEventListener('keydown', e => { const g = e.target.closest('.lane'); if (g && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); focusAlert(+g.dataset.n); } });
  $('#graph').addEventListener('click', graphClick);
  $('#q').addEventListener('input', () => { limit = 300; renderTable(); });
  $('#onlyBad').addEventListener('change', () => { limit = 300; renderTable(); });
  $('#more').addEventListener('click', () => { limit += 500; renderTable(); });
  $('#export').addEventListener('click', () => {
    const text = JSON.stringify(report(), null, 2);
    navigator.clipboard.writeText(text).then(() => toast('Rapport JSON copié dans le presse-papiers.'), () => toast('Copie refusée par le navigateur. Utilisez « Télécharger le rapport ».'));
  });
  const dl = $('#download');
  dl.hidden = inFrame;
  dl.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(report(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'packetlens-rapport-' + fileName.replace(/\.[^.]+$/, '') + '.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
  const roTl = new ResizeObserver(() => drawTimeline()); roTl.observe($('#tl'));
  const roG = new ResizeObserver(() => drawGraph()); roG.observe($('#gfig'));
  const roD = new ResizeObserver(() => A && drawDonut()); roD.observe($('#dfig'));
  if (document.fonts) document.fonts.ready.then(() => A && drawGraph());

  loadSample('incident');
}
