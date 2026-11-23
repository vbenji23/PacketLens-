/* PacketLens — lecture des fichiers PCAP / PCAPNG et décodage des protocoles.
   Tout se fait en JavaScript pur, octet par octet, sans bibliothèque. */
(function (root) {
  'use strict';
  const PL = root.PL = root.PL || {};

  const u16 = (d, o) => ((d[o] << 8) | d[o + 1]) >>> 0;
  const u32 = (d, o) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;
  const hex2 = b => b.toString(16).padStart(2, '0');
  const mac = (d, o) => Array.from(d.subarray(o, o + 6), hex2).join(':');
  const ip4 = (d, o) => d[o] + '.' + d[o + 1] + '.' + d[o + 2] + '.' + d[o + 3];
  function ip6(d, o) {
    const p = [];
    for (let i = 0; i < 16; i += 2) p.push(u16(d, o + i).toString(16));
    return p.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::');
  }
  function txt(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }

  /* ---------- Lecture du conteneur ---------- */
  function readCapture(buf) {
    if (buf instanceof Uint8Array) buf = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    if (buf.byteLength < 24) throw new Error('Fichier trop petit pour être une capture réseau.');
    const dv = new DataView(buf);
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return readPcapng(buf, dv);
    let le, nano;
    if (magic === 0xa1b2c3d4) { le = false; nano = false; }
    else if (magic === 0xd4c3b2a1) { le = true; nano = false; }
    else if (magic === 0xa1b23c4d) { le = false; nano = true; }
    else if (magic === 0x4d3cb2a1) { le = true; nano = true; }
    else throw new Error("Format non reconnu : ce fichier n'est ni un .pcap ni un .pcapng.");
    const link = dv.getUint32(20, le);
    const packets = [];
    let off = 24;
    while (off + 16 <= buf.byteLength) {
      const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le);
      const incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
      off += 16;
      if (off + incl > buf.byteLength) break; // capture tronquée
      packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), link, len: orig, data: new Uint8Array(buf, off, incl) });
      off += incl;
    }
    return { format: nano ? 'pcap (nanosecondes)' : 'pcap', link, packets };
  }

  function readPcapng(buf, dv) {
    let off = 0, le = true;
    const ifs = [], packets = [];
    while (off + 12 <= buf.byteLength) {
      const type0 = dv.getUint32(off, true);
      if (type0 === 0x0a0d0d0a) { le = dv.getUint32(off + 8, true) === 0x1a2b3c4d; ifs.length = 0; }
      const type = dv.getUint32(off, le);
      const blen = dv.getUint32(off + 4, le);
      if (blen < 12 || off + blen > buf.byteLength) break;
      if (type === 1) { // Interface Description Block
        const link = dv.getUint16(off + 8, le);
        let tsres = 6, o = off + 16;
        const end = off + blen - 4;
        while (o + 4 <= end) {
          const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && l >= 1) tsres = dv.getUint8(o + 4);
          o += 4 + ((l + 3) & ~3);
        }
        ifs.push({ link, div: (tsres & 0x80) ? Math.pow(2, tsres & 0x7f) : Math.pow(10, tsres) });
      } else if (type === 6) { // Enhanced Packet Block
        const id = dv.getUint32(off + 8, le);
        const hi = dv.getUint32(off + 12, le), lo = dv.getUint32(off + 16, le);
        const cap = dv.getUint32(off + 20, le), orig = dv.getUint32(off + 24, le);
        const itf = ifs[id] || { link: 1, div: 1e6 };
        packets.push({ ts: (hi * 4294967296 + lo) / itf.div, link: itf.link, len: orig, data: new Uint8Array(buf, off + 28, Math.min(cap, blen - 32)) });
      } else if (type === 3) { // Simple Packet Block
        const orig = dv.getUint32(off + 8, le);
        const itf = ifs[0] || { link: 1 };
        packets.push({ ts: 0, link: itf.link, len: orig, data: new Uint8Array(buf, off + 12, Math.min(orig, blen - 16)) });
      }
      off += blen;
    }
    return { format: 'pcapng', link: ifs[0] ? ifs[0].link : 1, packets };
  }

  /* ---------- Décodage d'un paquet ---------- */
  const QT = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
  const FLAGS = [[0x02, 'SYN'], [0x10, 'ACK'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x20, 'URG']];
  const flagStr = f => FLAGS.filter(x => f & x[0]).map(x => x[1]).join(', ');

  function decode(p, i) {
    const d = p.data;
    const r = { i, ts: p.ts, len: p.len, proto: '?', src: '', dst: '', info: '' };
    try {
      let o = 0, et = 0;
      if (p.link === 1) {
        if (d.length < 14) { r.info = 'Trame tronquée'; return r; }
        r.dstMac = mac(d, 0); r.srcMac = mac(d, 6); et = u16(d, 12); o = 14;
        while (et === 0x8100 || et === 0x88a8) { et = u16(d, o + 2); o += 4; } // VLAN
      } else if (p.link === 113) { et = u16(d, 14); o = 16; } // Linux cooked
      else if (p.link === 101 || p.link === 228 || p.link === 229) { et = (d[0] >> 4) === 6 ? 0x86dd : 0x0800; }
      else if (p.link === 0) { et = (d[0] === 2 || d[3] === 2) ? 0x0800 : 0x86dd; o = 4; } // loopback BSD
      else { r.proto = 'Lien ' + p.link; r.info = 'Type de lien non pris en charge'; return r; }
      if (et === 0x0806) return arp(d, o, r);
      if (et === 0x0800) return ipv4(d, o, r);
      if (et === 0x86dd) return ipv6(d, o, r);
      r.proto = 'Ethernet'; r.info = 'EtherType 0x' + et.toString(16).padStart(4, '0');
    } catch (e) { r.info = 'Paquet tronqué ou malformé'; }
    return r;
  }

  function arp(d, o, r) {
    const op = u16(d, o + 6);
    r.proto = 'ARP';
    r.arp = { op, sha: mac(d, o + 8), spa: ip4(d, o + 14), tha: mac(d, o + 18), tpa: ip4(d, o + 24) };
    r.src = r.arp.spa; r.dst = r.arp.tpa;
    r.info = op === 1 ? `Qui a ${r.arp.tpa} ? Répondre à ${r.arp.spa}` : `${r.arp.spa} est à ${r.arp.sha}`;
    return r;
  }

  function ipv4(d, o, r) {
    const ihl = (d[o] & 15) * 4, proto = d[o + 9], tot = u16(d, o + 2);
    r.src = ip4(d, o + 12); r.dst = ip4(d, o + 16); r.ttl = d[o + 8];
    const end = Math.min(d.length, tot ? o + tot : d.length);
    return l4(d, o + ihl, end, proto, r);
  }

  function ipv6(d, o, r) {
    r.src = ip6(d, o + 8); r.dst = ip6(d, o + 24);
    return l4(d, o + 40, Math.min(d.length, o + 40 + u16(d, o + 4)), d[o + 6], r);
  }

  function l4(d, o, end, proto, r) {
    if (proto === 6) {
      r.proto = 'TCP'; r.sport = u16(d, o); r.dport = u16(d, o + 2); r.seq = u32(d, o + 4);
      r.flags = d[o + 13];
      const pay = d.subarray(o + (d[o + 12] >> 4) * 4, end);
      r.plen = pay.length;
      r.info = `${r.sport} → ${r.dport} [${flagStr(r.flags)}]` + (pay.length ? ` ${pay.length} o` : '');
      if (pay.length) app(pay, r);
      return r;
    }
    if (proto === 17) {
      r.proto = 'UDP'; r.sport = u16(d, o); r.dport = u16(d, o + 2);
      const pay = d.subarray(o + 8, end);
      r.plen = pay.length;
      r.info = `${r.sport} → ${r.dport} ${pay.length} o`;
      if (r.sport === 53 || r.dport === 53 || r.sport === 5353 || r.dport === 5353) dns(pay, r);
      return r;
    }
    if (proto === 1 || proto === 58) {
      r.proto = proto === 1 ? 'ICMP' : 'ICMPv6'; r.icmpType = d[o];
      r.info = icmpName(proto, d[o]);
      return r;
    }
    r.proto = 'IP/' + proto;
    return r;
  }

  function icmpName(proto, t) {
    const v4 = { 0: 'Réponse echo (ping)', 3: 'Destination injoignable', 5: 'Redirection', 8: 'Requête echo (ping)', 11: 'TTL expiré' };
    const v6 = { 1: 'Destination injoignable', 128: 'Requête echo (ping)', 129: 'Réponse echo (ping)', 133: 'Sollicitation de routeur', 134: 'Annonce de routeur', 135: 'Sollicitation de voisin', 136: 'Annonce de voisin' };
    return (proto === 1 ? v4 : v6)[t] || 'Type ' + t;
  }

  function readName(p, o) {
    const parts = [];
    let next = -1, guard = 0;
    while (o < p.length && guard++ < 128) {
      const l = p[o];
      if (l === 0) { o++; break; }
      if ((l & 0xc0) === 0xc0) { if (next < 0) next = o + 2; o = ((l & 0x3f) << 8) | p[o + 1]; continue; }
      parts.push(txt(p.subarray(o + 1, o + 1 + l)));
      o += 1 + l;
    }
    return { name: parts.join('.'), next: next < 0 ? o : next };
  }

  function dns(p, r) {
    if (p.length < 17) return;
    const flags = u16(p, 2);
    const nm = readName(p, 12);
    if (!nm.name) return;
    const qt = u16(p, nm.next);
    r.proto = 'DNS';
    r.dns = { id: u16(p, 0), resp: !!(flags & 0x8000), name: nm.name, qtype: qt, rcode: flags & 15, an: u16(p, 6) };
    r.info = (r.dns.resp ? 'Réponse ' : 'Requête ') + (QT[qt] || qt) + ' ' + nm.name + (r.dns.resp && r.dns.rcode === 3 ? ' (NXDOMAIN)' : '');
  }

  function headers(s) {
    const h = {};
    const lines = s.split(/\r?\n/);
    for (let k = 1; k < lines.length && lines[k]; k++) {
      const c = lines[k].indexOf(':');
      if (c > 0) h[lines[k].slice(0, c).trim().toLowerCase()] = lines[k].slice(c + 1).trim();
    }
    return h;
  }

  function findSni(p) {
    try {
      let o = 5 + 4 + 2 + 32;
      o += 1 + p[o];
      o += 2 + u16(p, o);
      o += 1 + p[o];
      const end = Math.min(p.length, o + 2 + u16(p, o));
      o += 2;
      while (o + 4 <= end) {
        const t = u16(p, o), l = u16(p, o + 2);
        if (t === 0) return txt(p.subarray(o + 9, o + 9 + u16(p, o + 7)));
        o += 4 + l;
      }
    } catch (e) { /* pas de SNI */ }
    return '';
  }

  function app(pay, r) {
    const s = txt(pay.subarray(0, Math.min(pay.length, 4096)));
    const has = port => r.sport === port || r.dport === port;
    if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+ HTTP\/1\.[01]\r?\n/.test(s)) {
      const line = s.split(/\r?\n/)[0], parts = line.split(' ');
      const sep = s.search(/\r?\n\r?\n/);
      r.proto = 'HTTP';
      r.http = { req: true, method: parts[0], path: parts[1], headers: headers(s), body: sep >= 0 ? s.slice(sep).replace(/^\r?\n\r?\n/, '') : '' };
      r.http.host = r.http.headers.host || r.dst;
      r.info = line;
      return;
    }
    if (/^HTTP\/1\.[01] \d{3}/.test(s)) {
      r.proto = 'HTTP'; r.http = { req: false, status: +s.slice(9, 12) };
      r.info = s.split(/\r?\n/)[0];
      return;
    }
    if (has(21)) {
      r.proto = 'FTP'; r.ftp = s.trim();
      r.info = r.ftp.split(/\r?\n/)[0].replace(/^PASS .*/i, 'PASS ••••••');
      return;
    }
    if (has(22)) {
      r.proto = 'SSH';
      if (s.startsWith('SSH-')) { r.ssh = s.trim(); r.info = 'Bannière ' + r.ssh; }
      else r.info = `Données chiffrées ${pay.length} o`;
      return;
    }
    if (has(443) || has(8443)) {
      r.proto = 'TLS';
      if (pay[0] === 22 && pay[5] === 1) {
        const sni = findSni(pay);
        r.tls = { sni };
        r.info = 'Client Hello' + (sni ? ' · ' + sni : '');
      } else r.info = `Données chiffrées ${pay.length} o`;
      return;
    }
    if (has(23)) { r.proto = 'Telnet'; r.info = `Telnet ${pay.length} o (en clair)`; return; }
    if (has(445) || has(139)) { r.proto = 'SMB'; r.info = `SMB ${pay.length} o`; }
  }

  Object.assign(PL, { readCapture, decode, txt, QT });
})(typeof window !== 'undefined' ? window : globalThis);
