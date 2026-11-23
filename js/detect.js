/* PacketLens — statistiques et règles de détection.
   Chaque règle lit la liste des paquets décodés et produit des alertes. */
(function (root) {
  'use strict';
  const PL = root.PL = root.PL || {};

  const RANK = { none: 0, info: 1, moy: 2, haute: 3, crit: 4 };
  const AUTH = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 110: 'POP3', 143: 'IMAP', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC' };
  const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd)/i.test(ip);

  function fmtDur(s) {
    if (s < 1) return Math.round(s * 1000) + ' ms';
    if (s < 60) return s.toFixed(1).replace('.', ',') + ' s';
    const m = Math.floor(s / 60), r = Math.round(s % 60);
    return m + ' min' + (r ? ' ' + r + ' s' : '');
  }
  function mask(p) {
    if (!p) return '(vide)';
    if (p.length <= 2) return '••';
    return p[0] + '•'.repeat(Math.min(8, p.length - 2)) + p[p.length - 1];
  }
  function b64(s) {
    try { return typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('latin1'); } catch (e) { return ''; }
  }
  function urlDec(s) {
    try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; }
  }
  function entropy(str) {
    if (!str) return 0;
    const f = {};
    for (const c of str) f[c] = (f[c] || 0) + 1;
    let e = 0;
    for (const k in f) { const p = f[k] / str.length; e -= p * Math.log2(p); }
    return e;
  }
  const push = (m, k, mk) => { let v = m.get(k); if (!v) { v = mk(); m.set(k, v); } return v; };

  function analyze(cap) {
    const pk = cap.packets.map(PL.decode);
    let t0 = Infinity, t1 = -Infinity, bytes = 0;
    for (const r of pk) { if (r.ts < t0) t0 = r.ts; if (r.ts > t1) t1 = r.ts; bytes += r.len; }
    if (!pk.length) t0 = t1 = 0;

    /* ---------- Statistiques ---------- */
    const protos = new Map(), hosts = new Map(), edges = new Map(), macToIp = new Map();
    const H = ip => push(hosts, ip, () => ({ ip, macs: new Set(), out: 0, inn: 0, bout: 0, bin: 0, protos: new Set(), ports: new Set(), peers: new Set(), role: '', alerts: [], local: isPrivate(ip) }));
    for (const r of pk) {
      protos.set(r.proto, (protos.get(r.proto) || 0) + 1);
      if (!r.src || !r.dst) continue;
      if (r.arp && r.arp.op === 1) { H(r.src).macs.add(r.arp.sha); continue; } // une simple question ARP ne crée pas de conversation
      const a = H(r.src), b = H(r.dst);
      a.out++; a.bout += r.len; b.inn++; b.bin += r.len;
      a.protos.add(r.proto); b.protos.add(r.proto);
      a.peers.add(r.dst); b.peers.add(r.src);
      if (r.arp) a.macs.add(r.arp.sha);
      else if (r.srcMac && a.local) { a.macs.add(r.srcMac); push(macToIp, r.srcMac, () => new Set()).add(r.src); }
      if (r.flags !== undefined && (r.flags & 0x12) === 0x02) a.ports.add(r.dport);
      else if (r.proto === 'UDP' || r.proto === 'DNS') { if (r.dport < r.sport) a.ports.add(r.dport); }
      const k = r.src < r.dst ? r.src + '|' + r.dst : r.dst + '|' + r.src;
      const e = push(edges, k, () => ({ a: r.src < r.dst ? r.src : r.dst, b: r.src < r.dst ? r.dst : r.src, bytes: 0, pkts: 0, protos: new Set() }));
      e.bytes += r.len; e.pkts++; e.protos.add(r.proto);
    }

    const alerts = [];
    const add = a => alerts.push(Object.assign({ te: a.ts, srcRole: 'attaquant', dstRole: 'cible' }, a));

    /* ---------- 1. Scan de ports TCP ---------- */
    const syns = new Map(), open = new Map();
    for (const r of pk) {
      if (r.flags === undefined) continue;
      if ((r.flags & 0x12) === 0x02) {
        const s = push(syns, r.src + '>' + r.dst, () => ({ src: r.src, dst: r.dst, ports: new Set(), t1: r.ts, t2: r.ts, idx: [] }));
        if (!s.ports.has(r.dport)) { s.ports.add(r.dport); s.t2 = r.ts; s.idx.push(r.i); }
      } else if ((r.flags & 0x12) === 0x12) push(open, r.dst + '>' + r.src, () => new Set()).add(r.sport);
    }
    for (const s of syns.values()) {
      if (s.ports.size < 20 || s.t2 - s.t1 > 600) continue;
      const op = [...(open.get(s.src + '>' + s.dst) || [])].sort((x, y) => x - y);
      add({
        sev: 'haute', type: 'scan', title: 'Scan de ports', src: s.src, dst: s.dst, ts: s.t1, te: s.t2, idx: s.idx,
        detail: `${s.src} a sondé ${s.ports.size} ports TCP de ${s.dst} en ${fmtDur(s.t2 - s.t1)} avec des paquets SYN (scan « semi-ouvert », typique de nmap -sS). Ports ouverts trouvés : ${op.length ? op.join(', ') : 'aucun'}.`,
        mitre: ['T1046', 'Network Service Discovery'],
        conseil: "Bloquer l'IP source, fermer les services inutiles et surveiller ce que l'attaquant fait ensuite sur les ports ouverts."
      });
    }

    /* ---------- 2. Balayage ARP et ping sweep (découverte d'hôtes) ---------- */
    const arpReq = new Map(), pings = new Map();
    for (const r of pk) {
      if (r.arp && r.arp.op === 1 && r.arp.spa !== r.arp.tpa) {
        const s = push(arpReq, r.arp.spa, () => ({ dst: new Set(), t1: r.ts, t2: r.ts, idx: [] }));
        if (!s.dst.has(r.arp.tpa)) { s.dst.add(r.arp.tpa); s.t2 = r.ts; s.idx.push(r.i); }
      }
      if ((r.proto === 'ICMP' && r.icmpType === 8) || (r.proto === 'ICMPv6' && r.icmpType === 128)) {
        const s = push(pings, r.src, () => ({ dst: new Set(), t1: r.ts, t2: r.ts, idx: [] }));
        if (!s.dst.has(r.dst)) { s.dst.add(r.dst); s.t2 = r.ts; s.idx.push(r.i); }
      }
    }
    const answered = new Set(pk.filter(r => r.arp && r.arp.op === 2).map(r => r.arp.spa + '>' + r.arp.tpa));
    for (const [src, s] of arpReq) {
      if (s.dst.size < 20 || s.t2 - s.t1 > 120) continue;
      const live = [...s.dst].filter(ip => answered.has(ip + '>' + src));
      add({
        sev: 'moy', type: 'arpsweep', title: "Balayage ARP (découverte d'hôtes)", src, dst: s.dst.size + ' adresses', ts: s.t1, te: s.t2, idx: s.idx,
        detail: `${src} a demandé l'adresse MAC de ${s.dst.size} IP différentes en ${fmtDur(s.t2 - s.t1)}. ${live.length} machine(s) ont répondu : ${live.join(', ') || 'aucune'}. C'est la première étape d'une reconnaissance (nmap -sn, netdiscover).`,
        mitre: ['T1018', 'Remote System Discovery'],
        conseil: 'Identifier la machine source : un poste qui balaye tout le réseau sans raison doit être isolé et examiné.'
      });
    }
    for (const [src, s] of pings) {
      if (s.dst.size < 10 || s.t2 - s.t1 > 300) continue;
      add({
        sev: 'moy', type: 'pingsweep', title: 'Ping sweep', src, dst: s.dst.size + ' adresses', ts: s.t1, te: s.t2, idx: s.idx,
        detail: `${src} a envoyé des pings à ${s.dst.size} machines différentes en ${fmtDur(s.t2 - s.t1)} pour savoir lesquelles sont allumées.`,
        mitre: ['T1018', 'Remote System Discovery'],
        conseil: 'Vérifier si cette machine a une raison légitime de superviser le réseau, sinon la considérer comme suspecte.'
      });
    }

    /* ---------- 3. Brute force (connexions répétées vers un service d'authentification) ---------- */
    const tries = new Map(), banners = new Map();
    for (const r of pk) {
      if (r.ssh && r.dport === 22) banners.set(r.src, r.ssh);
      if (r.flags === undefined || (r.flags & 0x12) !== 0x02 || !AUTH[r.dport]) continue;
      const t = push(tries, r.src + '>' + r.dst + ':' + r.dport, () => ({ src: r.src, dst: r.dst, port: r.dport, ts: [], idx: [] }));
      t.ts.push(r.ts); t.idx.push(r.i);
    }
    for (const t of tries.values()) {
      const n = t.ts.length, span = t.ts[n - 1] - t.ts[0];
      if (n < 10 || span > 900) continue;
      const svc = AUTH[t.port], ban = banners.get(t.src);
      const tool = ban && /libssh|paramiko|go|hydra|medusa|ncrack/i.test(ban) ? ` Le client s'annonce « ${ban} », une bibliothèque utilisée par les outils d'attaque comme Hydra, pas un vrai client SSH.` : '';
      add({
        sev: 'haute', type: 'brute', title: `Brute force ${svc}`, src: t.src, dst: t.dst + ':' + t.port, ts: t.ts[0], te: t.ts[n - 1], idx: t.idx,
        detail: `${n} connexions ${svc} de ${t.src} vers ${t.dst} en ${fmtDur(span)} (environ ${Math.round(n / Math.max(span / 60, 1 / 60))} par minute).${tool}`,
        mitre: ['T1110', 'Brute Force'],
        conseil: `Bloquer l'IP (fail2ban), interdire la connexion ${svc} par mot de passe et vérifier dans les logs du serveur si une tentative a réussi.`
      });
    }

    /* ---------- 4. FTP : échecs répétés et identifiants en clair ---------- */
    const ftpUser = new Map(), ftpPending = new Map(), ftpStats = new Map(), ftpOk = [];
    for (const r of pk) {
      if (r.proto !== 'FTP') continue;
      if (r.dport === 21) {
        const flow = r.src + ':' + r.sport + '>' + r.dst;
        let m;
        if ((m = /^USER (.+)/i.exec(r.ftp))) ftpUser.set(flow, m[1].trim());
        else if ((m = /^PASS (.*)/i.exec(r.ftp))) ftpPending.set(flow, { user: ftpUser.get(flow) || '?', pass: m[1].trim(), i: r.i, ts: r.ts });
      } else if (r.sport === 21) {
        const flow = r.dst + ':' + r.dport + '>' + r.src;
        const p = ftpPending.get(flow);
        if (!p) continue;
        const code = parseInt(r.ftp.slice(0, 3), 10);
        const st = push(ftpStats, r.dst + '>' + r.src, () => ({ src: r.dst, dst: r.src, fail: 0, users: new Set(), idx: [], t1: p.ts, t2: r.ts, ok: null }));
        if (code === 530) { st.fail++; st.users.add(p.user); st.idx.push(p.i, r.i); st.t2 = r.ts; }
        else if (code === 230) { const ok = Object.assign({ src: r.dst, dst: r.src, ri: r.i }, p); if (st.fail) { st.ok = ok; st.idx.push(p.i, r.i); st.t2 = r.ts; } ftpOk.push(ok); }
        ftpPending.delete(flow);
      }
    }
    const bruteFtp = new Set();
    for (const st of ftpStats.values()) {
      if (st.fail < 5) continue;
      bruteFtp.add(st.src + '>' + st.dst);
      add({
        sev: st.ok ? 'crit' : 'haute', type: 'brute', title: st.ok ? 'Brute force FTP réussi' : 'Brute force FTP', src: st.src, dst: st.dst + ':21', ts: st.t1, te: st.t2, idx: st.idx,
        detail: `${st.fail} mots de passe refusés (code 530) pour ${[...st.users].join(', ')}.` + (st.ok ? ` Puis connexion acceptée (code 230) avec le compte « ${st.ok.user} » et le mot de passe ${mask(st.ok.pass)}, visible en clair dans la capture. L'attaquant a désormais accès au serveur.` : ' Aucune tentative réussie dans la capture.'),
        mitre: ['T1110.001', 'Password Guessing'],
        conseil: st.ok ? `Changer immédiatement le mot de passe de « ${st.ok.user} », couper l'accès FTP depuis l'extérieur, remplacer FTP par SFTP et vérifier les fichiers consultés.` : "Bloquer l'IP source et remplacer FTP par SFTP."
      });
    }

    /* ---------- 5. Identifiants en clair (HTTP, FTP) ---------- */
    const seen = new Set();
    const cred = (r, proto, user, pass, where) => {
      const k = r.src + '>' + r.dst + '|' + user + '|' + pass;
      if (seen.has(k)) return;
      seen.add(k);
      add({
        sev: 'haute', type: 'creds', title: `Identifiants en clair (${proto})`, src: r.src, dst: r.dst, ts: r.ts, idx: [r.i], srcRole: 'exposé', dstRole: '',
        detail: `Le compte « ${user || '?'} » et son mot de passe ${mask(pass)} circulent sans chiffrement vers ${where}. N'importe qui sur le réseau peut les lire (le mot de passe est masqué ici).`,
        mitre: ['T1552', 'Unsecured Credentials'],
        conseil: `Changer ce mot de passe et passer le service en ${proto === 'FTP' ? 'SFTP' : 'HTTPS'} pour chiffrer les échanges.`
      });
    };
    const PASS_RE = /(?:^|[?&])(pass|password|passwd|pwd|mdp|mot_?de_?passe|motdepasse)=([^&\s]*)/i;
    const USER_RE = /(?:^|[?&])(user|username|login|email|identifiant|utilisateur|uname)=([^&\s]*)/i;
    for (const r of pk) {
      if (!r.http || !r.http.req) continue;
      const where = 'http://' + r.http.host + r.http.path.split('?')[0];
      const auth = r.http.headers.authorization;
      if (auth && /^basic\s+/i.test(auth)) {
        const dec = b64(auth.replace(/^basic\s+/i, '').trim()), c = dec.indexOf(':');
        if (c >= 0) cred(r, 'HTTP Basic', dec.slice(0, c), dec.slice(c + 1), where);
      }
      for (const blob of [r.http.body, (r.http.path.split('?')[1] || '')]) {
        const pm = PASS_RE.exec(blob);
        if (pm) { const um = USER_RE.exec(blob); cred(r, 'HTTP', um ? urlDec(um[2]) : '', urlDec(pm[2]), where); }
      }
    }
    for (const ok of ftpOk) {
      if (bruteFtp.has(ok.src + '>' + ok.dst)) continue;
      cred({ src: ok.src, dst: ok.dst, ts: ok.ts, i: ok.i }, 'FTP', ok.user, ok.pass, 'le serveur FTP ' + ok.dst);
    }

    /* ---------- 6. ARP spoofing ---------- */
    const ipMacs = new Map(), macIps = new Map(), replies = new Map();
    for (const r of pk) {
      if (!r.arp || r.arp.spa === '0.0.0.0') continue;
      const m = push(ipMacs, r.arp.spa, () => new Map());
      const e = push(m, r.arp.sha, () => ({ n: 0, t1: r.ts, t2: r.ts, idx: [] }));
      e.n++; e.t2 = r.ts; e.idx.push(r.i);
      push(macIps, r.arp.sha, () => new Set()).add(r.arp.spa);
      if (r.arp.op === 2) replies.set(r.arp.sha, (replies.get(r.arp.sha) || 0) + 1);
    }
    const spoof = new Map();
    for (const [ip, m] of ipMacs) {
      if (m.size < 2) continue;
      const macs = [...m.keys()];
      const score = x => (macIps.get(x).size > 1 ? 1000 : 0) + (replies.get(x) || 0) * 10 + m.get(x).t1 / 1e9;
      const sus = macs.sort((x, y) => score(y) - score(x))[0];
      const s = push(spoof, sus, () => ({ ips: [], legit: [], t1: Infinity, t2: 0, idx: [] }));
      const e = m.get(sus);
      s.ips.push(ip); s.legit.push(...macs.filter(x => x !== sus).map(x => ip + ' → ' + x));
      s.t1 = Math.min(s.t1, e.t1); s.t2 = Math.max(s.t2, e.t2); s.idx.push(...e.idx);
    }
    for (const [sus, s] of spoof) {
      const own = [...(macToIp.get(sus) || [])].filter(ip => !s.ips.includes(ip));
      const who = own[0] || sus;
      const stolen = pk.filter(r => !r.arp && r.dstMac === sus && r.src && r.dst !== who && !own.includes(r.dst)).length;
      add({
        sev: 'crit', type: 'arpspoof', title: 'ARP spoofing (homme du milieu)', src: who, dst: s.ips.join(', '), ts: s.t1, te: s.t2, idx: s.idx.sort((x, y) => x - y),
        detail: `La carte réseau ${sus}${own[0] ? ' (' + own[0] + ')' : ''} envoie ${replies.get(sus) || 0} réponses ARP non sollicitées pour se faire passer pour ${s.ips.join(' et ')}. Les vraies adresses : ${s.legit.join(' ; ')}. ${stolen} paquet(s) des victimes ont ainsi été envoyés à l'attaquant au lieu de leur vraie destination.`,
        mitre: ['T1557.002', 'ARP Cache Poisoning'],
        conseil: "Débrancher la machine de l'attaquant, activer la protection Dynamic ARP Inspection sur le switch et considérer comme volés tous les mots de passe passés en clair pendant l'attaque."
      });
    }

    /* ---------- 7. Tunnel DNS (exfiltration cachée dans des requêtes DNS) ---------- */
    const dz = new Map();
    for (const r of pk) {
      if (!r.dns || r.dns.resp) continue;
      const labels = r.dns.name.toLowerCase().split('.').filter(Boolean);
      if (labels.length < 3 || /\.arpa$/.test(r.dns.name)) continue;
      const base = labels.slice(-2).join('.'), sub = labels.slice(0, -2);
      const z = push(dz, base, () => ({ names: new Set(), n: 0, len: 0, max: 0, chars: '', qt: new Map(), src: new Set(), t1: r.ts, t2: r.ts, idx: [] }));
      z.n++; z.t2 = r.ts; z.idx.push(r.i); z.src.add(r.src);
      if (!z.names.has(r.dns.name)) {
        z.names.add(r.dns.name);
        const j = sub.join('');
        z.len += j.length; z.max = Math.max(z.max, ...sub.map(l => l.length));
        if (z.chars.length < 20000) z.chars += j;
      }
      z.qt.set(r.dns.qtype, (z.qt.get(r.dns.qtype) || 0) + 1);
    }
    for (const [base, z] of dz) {
      const u = z.names.size, avg = u ? z.len / u : 0, ent = entropy(z.chars);
      if (!((u >= 15 && (avg >= 25 || z.max >= 40) && ent >= 3.5) || u >= 150)) continue;
      const qt = [...z.qt].sort((a, b) => b[1] - a[1])[0][0];
      const src = [...z.src];
      add({
        sev: 'haute', type: 'dnstunnel', title: 'Tunnel DNS (exfiltration probable)', src: src.join(', '), dst: base, ts: z.t1, te: z.t2, idx: z.idx, srcRole: 'compromis', dstRole: '',
        detail: `${u} sous-domaines uniques de « ${base} » demandés par ${src.join(', ')}, de ${Math.round(avg)} caractères en moyenne (blocs jusqu'à ${z.max}) et très aléatoires (entropie ${ent.toFixed(2).replace('.', ',')} bits par caractère). Requêtes surtout de type ${PL.QT[qt] || qt}. Un vrai site n'a pas ce profil : des données sont encodées dans les noms, environ ${(z.len * 5 / 8 / 1024).toFixed(1).replace('.', ',')} Ko envoyés.`,
        mitre: ['T1071.004', 'Application Layer Protocol: DNS'],
        conseil: `Bloquer le domaine ${base} sur le résolveur DNS, isoler ${src[0]} et chercher le programme malveillant qui envoie ces requêtes.`
      });
    }

    /* ---------- Synthèse ---------- */
    alerts.sort((a, b) => a.ts - b.ts);
    const bad = new Map();
    const ROLE = { attaquant: 4, compromis: 3, cible: 2, 'exposé': 1, '': 0 };
    alerts.forEach((a, k) => {
      a.n = k + 1;
      for (const i of a.idx) if (!bad.has(i) || RANK[bad.get(i)] < RANK[a.sev]) bad.set(i, a.sev);
      const pairs = [[a.src, a.srcRole]].concat(String(a.dst).split(', ').map(d => [d.split(':')[0], a.dstRole]));
      for (const [ip, role] of pairs) {
        const h = hosts.get(ip);
        if (!h) continue;
        h.alerts.push(a.n);
        if (ROLE[role] > ROLE[h.role]) h.role = role;
      }
    });
    const worst = alerts.reduce((w, a) => RANK[a.sev] > RANK[w] ? a.sev : w, 'none');

    return {
      pk, t0, t1, bytes, alerts, bad, worst,
      protos: [...protos].sort((a, b) => b[1] - a[1]),
      hosts: [...hosts.values()].sort((a, b) => (b.bout + b.bin) - (a.bout + a.bin)),
      edges: [...edges.values()]
    };
  }

  Object.assign(PL, { analyze, fmtDur, mask, RANK, isPrivate });
})(typeof window !== 'undefined' ? window : globalThis);
