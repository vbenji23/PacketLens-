/* PacketLens — générateur de captures d'exemple.
   Fabrique de vrais fichiers .pcap (lisibles par Wireshark) qui simulent un petit réseau
   d'entreprise attaqué. Toutes les adresses sont privées ou réservées à la documentation
   (192.168.1.0/24, 203.0.113.0/24, 198.51.100.0/24, domaines .example) : aucune donnée réelle. */
(function (root) {
  'use strict';
  const PL = root.PL = root.PL || {};

  function rng(seed) {
    return function () {
      seed = (seed + 0x6D2B79F5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const S = s => Array.from(s, c => c.charCodeAt(0) & 255);
  const MAC = s => s.split(':').map(h => parseInt(h, 16));
  const IP = s => s.split('.').map(Number);
  const u16 = n => [(n >> 8) & 255, n & 255];
  const u24 = n => [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  const u32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const b64e = s => typeof btoa === 'function' ? btoa(s) : Buffer.from(s, 'latin1').toString('base64');

  function csum(b) {
    let s = 0;
    for (let i = 0; i < b.length; i += 2) s += (b[i] << 8) + (b[i + 1] || 0);
    while (s >>> 16) s = (s & 0xffff) + (s >>> 16);
    return (~s) & 0xffff;
  }
  function ipv4(src, dst, proto, pl, id, ttl) {
    const h = [0x45, 0, ...u16(20 + pl.length), ...u16(id & 0xffff), 0x40, 0, ttl, proto, 0, 0, ...IP(src), ...IP(dst)];
    const c = csum(h); h[10] = c >> 8; h[11] = c & 255;
    return h.concat(pl);
  }
  const l4sum = (src, dst, proto, seg) => csum([...IP(src), ...IP(dst), 0, proto, ...u16(seg.length), ...seg]);
  function tcpSeg(src, dst, sp, dp, flags, seq, ack, pl) {
    const s = [...u16(sp), ...u16(dp), ...u32(seq), ...u32(ack), 0x50, flags, ...u16(64240), 0, 0, 0, 0].concat(pl);
    const c = l4sum(src, dst, 6, s); s[16] = c >> 8; s[17] = c & 255;
    return s;
  }
  function udpSeg(src, dst, sp, dp, pl) {
    const s = [...u16(sp), ...u16(dp), ...u16(8 + pl.length), 0, 0].concat(pl);
    let c = l4sum(src, dst, 17, s); if (c === 0) c = 0xffff;
    s[6] = c >> 8; s[7] = c & 255;
    return s;
  }

  /* ---------- Le réseau simulé ---------- */
  const BCAST = 'ff:ff:ff:ff:ff:ff';
  const GW = { ip: '192.168.1.1', mac: 'a4:2b:b0:12:34:01', name: 'box / passerelle' };
  const SRV = { ip: '192.168.1.10', mac: '00:1c:42:9a:10:10', name: 'srv-fichiers' };
  const COMPTA = { ip: '192.168.1.23', mac: '3c:52:82:4e:23:23', name: 'poste compta' };
  const DEV = { ip: '192.168.1.31', mac: 'f0:18:98:31:31:31', name: 'poste dev' };
  const RH = { ip: '192.168.1.42', mac: 'd8:bb:c1:42:42:42', name: 'poste RH' };
  const ATT = { ip: '192.168.1.66', mac: '08:00:27:66:66:66', name: 'VM Kali' };
  const LAN = [GW, SRV, COMPTA, DEV, RH];
  const SITES = [
    ['www.example.com', '203.0.113.10'], ['cdn.example.net', '203.0.113.25'], ['mail.example.org', '198.51.100.7'],
    ['api.example.com', '203.0.113.40'], ['docs.example.org', '198.51.100.20']
  ].map(([name, ip]) => ({ name, ip, mac: GW.mac, local: false }));
  const PORTAIL = { name: 'portail-rh.example.com', ip: '203.0.113.80', mac: GW.mac, local: false };
  const WORKERS = [COMPTA, DEV, RH];

  class Cap {
    constructor(seed) { this.r = rng(seed); this.t = Date.UTC(2026, 10, 23, 9, 12, 0) / 1000; this.pk = []; this.ipid = 0x1a00; }
    wait(s) { this.t += s; }
    jit(a, b) { return a + (b - a) * this.r(); }
    pick(a) { return a[Math.floor(this.r() * a.length)]; }
    rb(n) { const o = new Array(n); for (let i = 0; i < n; i++) o[i] = Math.floor(this.r() * 256); return o; }
    port() { return 49152 + Math.floor(this.r() * 16000); }
    seq() { return Math.floor(this.r() * 4294967295); }
    frame(srcMac, dstMac, type, pl) {
      this.t += 0.00004 + this.r() * 0.0003;
      this.pk.push({ ts: this.t, bytes: [...MAC(dstMac), ...MAC(srcMac), ...u16(type)].concat(pl) });
    }
    ip(a, b, proto, seg, via) { this.frame(a.mac, via || b.mac, 0x0800, ipv4(a.ip, b.ip, proto, seg, this.ipid++, a.local === false ? 54 : 64)); }
    tcp(a, b, sp, dp, fl, seq, ack, pl, via) { this.ip(a, b, 6, tcpSeg(a.ip, b.ip, sp, dp, fl, seq >>> 0, ack >>> 0, pl || []), via); }
    udp(a, b, sp, dp, pl) { this.ip(a, b, 17, udpSeg(a.ip, b.ip, sp, dp, pl)); }
    icmp(a, b, type, id, sq) {
      const m = [type, 0, 0, 0, ...u16(id), ...u16(sq), ...S('PacketLens ping 0123456789abcdefghij')];
      const c = csum(m); m[2] = c >> 8; m[3] = c & 255;
      this.ip(a, b, 1, m);
    }
    arp(op, shaMac, spa, thaMac, tpa, dstMac) {
      this.frame(shaMac, dstMac, 0x0806, [0, 1, 8, 0, 6, 4, ...u16(op), ...MAC(shaMac), ...IP(spa), ...MAC(thaMac), ...IP(tpa)].concat(new Array(18).fill(0)));
    }
    /* Une connexion TCP complète, avec numéros de séquence cohérents. */
    session(c, s, dp, opt) {
      opt = opt || {};
      const cap = this, cp = opt.sport || this.port(), rtt = opt.rtt || 0.0015, via = opt.via;
      let cs = this.seq(), ss = this.seq();
      const B = d => typeof d === 'string' ? S(d) : d;
      const o = {
        open() {
          cap.tcp(c, s, cp, dp, 0x02, cs, 0, [], via); cap.wait(rtt);
          cap.tcp(s, c, dp, cp, 0x12, ss, cs + 1); cs++; ss++; cap.wait(rtt / 4);
          cap.tcp(c, s, cp, dp, 0x10, cs, ss, [], via);
          return o;
        },
        c(d) { const b = B(d); cap.tcp(c, s, cp, dp, 0x18, cs, ss, b, via); cs += b.length; cap.wait(rtt); cap.tcp(s, c, dp, cp, 0x10, ss, cs); return o; },
        s(d) { const b = B(d); cap.wait(rtt / 2); cap.tcp(s, c, dp, cp, 0x18, ss, cs, b); ss += b.length; cap.wait(rtt / 4); cap.tcp(c, s, cp, dp, 0x10, cs, ss, [], via); return o; },
        pause(x) { cap.wait(x); return o; },
        close() {
          cap.tcp(c, s, cp, dp, 0x11, cs, ss, [], via); cs++; cap.wait(rtt);
          cap.tcp(s, c, dp, cp, 0x11, ss, cs); ss++; cap.wait(rtt / 4);
          cap.tcp(c, s, cp, dp, 0x10, cs, ss, [], via);
          return o;
        }
      };
      return o;
    }
    toPcap() {
      let total = 24;
      for (const p of this.pk) total += 16 + Math.max(60, p.bytes.length);
      const buf = new ArrayBuffer(total), dv = new DataView(buf), u8 = new Uint8Array(buf);
      dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
      dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
      let off = 24;
      for (const p of this.pk) {
        const len = Math.max(60, p.bytes.length);
        let sec = Math.floor(p.ts), us = Math.round((p.ts - sec) * 1e6);
        if (us >= 1e6) { sec++; us -= 1e6; }
        dv.setUint32(off, sec, true); dv.setUint32(off + 4, us, true);
        dv.setUint32(off + 8, len, true); dv.setUint32(off + 12, len, true);
        u8.set(p.bytes, off + 16);
        off += 16 + len;
      }
      return u8;
    }
  }

  /* ---------- Briques de trafic ---------- */
  function dnsName(n) { const o = []; for (const l of n.split('.')) o.push(l.length, ...S(l)); o.push(0); return o; }
  const dnsQ = (id, name, qt) => [...u16(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...dnsName(name), ...u16(qt), 0, 1];
  function dnsR(id, name, qt, ans) {
    const o = [...u16(id), 0x81, 0x80, 0, 1, ...u16(ans.length), 0, 0, 0, 0, ...dnsName(name), ...u16(qt), 0, 1];
    for (const a of ans) {
      const rd = a.ip ? IP(a.ip) : [a.txt.length, ...S(a.txt)];
      o.push(0xc0, 0x0c, ...u16(a.ip ? 1 : 16), 0, 1, ...u32(300), ...u16(rd.length), ...rd);
    }
    return o;
  }
  function lookup(cap, who, name, qt, ans) {
    const id = Math.floor(cap.r() * 65535), p = cap.port();
    cap.udp(who, GW, p, 53, dnsQ(id, name, qt)); cap.wait(cap.jit(0.004, 0.02));
    cap.udp(GW, who, 53, p, dnsR(id, name, qt, ans));
  }
  function clientHello(cap, host) {
    const ext = [0, 0, ...u16(host.length + 5), ...u16(host.length + 3), 0, ...u16(host.length), ...S(host)];
    const body = [3, 3, ...cap.rb(32), 32, ...cap.rb(32), 0, 4, 0x13, 0x01, 0x13, 0x02, 1, 0, ...u16(ext.length), ...ext];
    const hs = [1, ...u24(body.length), ...body];
    return [22, 3, 1, ...u16(hs.length), ...hs];
  }
  const http200 = body => `HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${body.length}\r\n\r\n${body}`;

  /* Trafic de bureau ordinaire : navigation HTTPS, intranet, partage de fichiers, pings. */
  function noise(cap, dur) {
    const end = cap.t + dur;
    while (cap.t < end) {
      const x = cap.r(), w = cap.pick(WORKERS);
      if (x < 0.5) {
        const site = cap.pick(SITES);
        lookup(cap, w, site.name, 1, [{ ip: site.ip }]);
        cap.session(w, site, 443, { rtt: 0.018 }).open().c(clientHello(cap, site.name)).s(cap.rb(1380)).s(cap.rb(640)).c(cap.rb(126)).s(cap.rb(Math.floor(cap.jit(300, 1400)))).close();
      } else if (x < 0.7) {
        cap.session(w, SRV, 80).open()
          .c('GET /intranet/actualites.html HTTP/1.1\r\nHost: intranet.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n')
          .s(http200('<!doctype html><title>Intranet</title><h1>Actualites</h1><p>Reunion d\'equipe jeudi 10h.</p>')).close();
      } else if (x < 0.85) {
        const id = Math.floor(cap.r() * 65535);
        cap.icmp(w, GW, 8, id, 1); cap.wait(0.0006); cap.icmp(GW, w, 0, id, 1);
      } else {
        cap.session(w, SRV, 445).open().c(cap.rb(180)).s(cap.rb(420)).c(cap.rb(90)).s(cap.rb(1200)).close();
      }
      cap.wait(cap.jit(0.4, 2.4));
    }
  }

  function arpSweep(cap) {
    const live = { [GW.ip]: GW, [SRV.ip]: SRV, [COMPTA.ip]: COMPTA, [DEV.ip]: DEV, [RH.ip]: RH };
    for (let i = 1; i <= 40; i++) {
      const ip = '192.168.1.' + i;
      if (ip === ATT.ip) continue;
      cap.arp(1, ATT.mac, ATT.ip, '00:00:00:00:00:00', ip, BCAST);
      if (live[ip]) { cap.wait(0.0007); cap.arp(2, live[ip].mac, ip, ATT.mac, ATT.ip, ATT.mac); }
      cap.wait(0.012);
    }
    for (const h of LAN) { cap.icmp(ATT, h, 8, 0x4c50, 1); cap.wait(0.0005); cap.icmp(h, ATT, 0, 0x4c50, 1); }
  }

  function portScan(cap) {
    const top = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
    const ports = [...new Set(top.concat(Array.from({ length: 120 }, (_, k) => k + 1)))];
    for (let k = ports.length - 1; k > 0; k--) { const j = Math.floor(cap.r() * (k + 1)); [ports[k], ports[j]] = [ports[j], ports[k]]; }
    const openP = new Set([21, 22, 80, 445]), sp = 61734;
    for (const p of ports) {
      const sq = cap.seq();
      cap.tcp(ATT, SRV, sp, p, 0x02, sq, 0);
      cap.wait(0.0004);
      if (openP.has(p)) { cap.tcp(SRV, ATT, p, sp, 0x12, cap.seq(), sq + 1); cap.wait(0.0002); cap.tcp(ATT, SRV, sp, p, 0x04, sq + 1, 0); }
      else cap.tcp(SRV, ATT, p, sp, 0x14, 0, sq + 1);
      cap.wait(cap.jit(0.002, 0.012));
    }
  }

  function sshBrute(cap, n) {
    for (let k = 0; k < n; k++) {
      cap.session(ATT, SRV, 22).open()
        .s('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n').c('SSH-2.0-libssh2_1.11.0\r\n')
        .c(cap.rb(640)).s(cap.rb(1080)).c(cap.rb(48)).s(cap.rb(64)).c(cap.rb(96)).pause(0.25).s(cap.rb(52)).close();
      cap.wait(cap.jit(1.1, 2.3));
    }
  }

  function sshLegit(cap) {
    cap.session(DEV, SRV, 22).open()
      .s('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n').c('SSH-2.0-OpenSSH_9.7\r\n')
      .c(cap.rb(1400)).s(cap.rb(1100)).c(cap.rb(48)).s(cap.rb(500)).c(cap.rb(120)).s(cap.rb(80))
      .pause(3).c(cap.rb(64)).s(cap.rb(900)).pause(4).c(cap.rb(64)).s(cap.rb(300)).close();
  }

  function ftpBrute(cap) {
    const guesses = ['admin', '123456', 'password', 'azerty', 'admin123', 'motdepasse', 'root', 'qwerty', 'Ete2026!'];
    for (let k = 0; k < guesses.length; k += 3) {
      const s = cap.session(ATT, SRV, 21).open().s('220 srv-fichiers FTP pret\r\n');
      for (const pw of guesses.slice(k, k + 3)) {
        s.c('USER admin\r\n').s('331 Mot de passe requis pour admin\r\n').c('PASS ' + pw + '\r\n').pause(cap.jit(0.6, 1.2));
        if (pw === 'Ete2026!') {
          s.s('230 Connexion reussie\r\n').c('PWD\r\n').s('257 "/" est le repertoire courant\r\n')
            .c('LIST\r\n').s('150 Liste des fichiers\r\n').s('226 Transfert termine\r\n').c('QUIT\r\n').s('221 Au revoir\r\n');
        } else s.s('530 Identifiants incorrects\r\n');
      }
      s.close();
      cap.wait(cap.jit(0.3, 0.8));
    }
  }

  function ftpLegit(cap) {
    cap.session(COMPTA, SRV, 21).open().s('220 srv-fichiers FTP pret\r\n')
      .c('USER compta\r\n').s('331 Mot de passe requis pour compta\r\n').c('PASS Factures2026\r\n').s('230 Connexion reussie\r\n')
      .c('CWD /bilans\r\n').s('250 Repertoire change\r\n').c('QUIT\r\n').s('221 Au revoir\r\n').close();
  }

  function arpSpoof(cap) {
    cap.arp(1, COMPTA.mac, COMPTA.ip, '00:00:00:00:00:00', GW.ip, BCAST); cap.wait(0.001);
    cap.arp(2, GW.mac, GW.ip, COMPTA.mac, COMPTA.ip, COMPTA.mac);
    noise(cap, 4);
    for (let k = 0; k < 14; k++) {
      cap.arp(2, ATT.mac, GW.ip, COMPTA.mac, COMPTA.ip, COMPTA.mac);
      cap.arp(2, ATT.mac, COMPTA.ip, GW.mac, GW.ip, GW.mac);
      if (k === 3) {
        const body = 'identifiant=m.durand&mot_de_passe=Soleil2026%21&rester_connecte=1';
        cap.session(COMPTA, PORTAIL, 80, { rtt: 0.02, via: ATT.mac }).open()
          .c(`POST /connexion HTTP/1.1\r\nHost: ${PORTAIL.name}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n\r\n${body}`)
          .s('HTTP/1.1 302 Found\r\nLocation: /accueil\r\nSet-Cookie: session=8f2c1d9e; HttpOnly\r\nContent-Length: 0\r\n\r\n').close();
      }
      if (k === 7) {
        cap.session(COMPTA, GW, 80, { via: ATT.mac }).open()
          .c(`GET /admin/ HTTP/1.1\r\nHost: 192.168.1.1\r\nAuthorization: Basic ${b64e('admin:Box-2026')}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`)
          .s(http200('<!doctype html><title>Box</title><h1>Administration</h1>')).close();
      }
      if (k % 3 === 1) {
        const site = cap.pick(SITES);
        cap.session(COMPTA, site, 443, { rtt: 0.022, via: ATT.mac }).open().c(clientHello(cap, site.name)).s(cap.rb(1380)).c(cap.rb(126)).close();
      }
      cap.wait(cap.jit(1.6, 2.2));
    }
  }

  function base32(bytes) {
    const A = 'abcdefghijklmnopqrstuvwxyz234567';
    let out = '', bits = 0, val = 0;
    for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits > 0) out += A[(val << (5 - bits)) & 31];
    return out;
  }
  function dnsTunnel(cap) {
    const noms = ['Martin', 'Bernard', 'Dubois', 'Thomas', 'Robert', 'Richard', 'Petit', 'Durand', 'Leroy', 'Moreau', 'Simon', 'Laurent', 'Lefebvre', 'Michel', 'Garcia'];
    let csv = 'client;email;contrat;montant\n';
    for (let k = 0; k < 40; k++) { const n = noms[k % noms.length]; csv += `${n} ${k + 1};${n.toLowerCase()}.${k + 1}@example.com;C-${1040 + k};${(Math.floor(cap.r() * 9000) + 500)}\n`; }
    const enc = base32(S('clients.csv|' + csv));
    lookup(cap, RH, 'beacon.data-sync.example', 16, [{ txt: 'ready' }]);
    cap.wait(1.5);
    for (let k = 0, q = 0; k < enc.length; k += 54, q++) {
      lookup(cap, RH, `${enc.slice(k, k + 54)}.${q.toString(16).padStart(3, '0')}.data-sync.example`, 16, [{ txt: 'ok' }]);
      cap.wait(cap.jit(0.25, 0.7));
      if (q % 9 === 4) noise(cap, 0.5);
    }
    lookup(cap, RH, 'fin.data-sync.example', 16, [{ txt: 'bye' }]);
  }

  /* ---------- Les captures proposées ---------- */
  const SAMPLES = {
    incident: {
      label: 'Incident complet', desc: "Une matinée d'attaque : reconnaissance, scan, brute force, ARP spoofing et exfiltration DNS.",
      build(c) {
        noise(c, 25); arpSweep(c); c.wait(2); portScan(c); noise(c, 20); sshBrute(c, 26); noise(c, 12);
        ftpBrute(c); noise(c, 10); ftpLegit(c); noise(c, 12); arpSpoof(c); noise(c, 15); dnsTunnel(c); noise(c, 12);
      }
    },
    scan: { label: 'Scan de ports', desc: 'Découverte du réseau par balayage ARP, puis scan SYN du serveur.', build(c) { noise(c, 15); arpSweep(c); c.wait(1.5); portScan(c); noise(c, 15); } },
    brute: { label: 'Brute force', desc: 'Hydra contre SSH, puis devinette de mots de passe FTP qui finit par réussir.', build(c) { noise(c, 10); sshBrute(c, 30); noise(c, 6); ftpBrute(c); noise(c, 10); } },
    arp: { label: 'ARP spoofing', desc: "Empoisonnement ARP d'un poste : son trafic passe par l'attaquant, des mots de passe fuient.", build(c) { noise(c, 10); arpSpoof(c); noise(c, 10); } },
    dns: { label: 'Tunnel DNS', desc: "Un poste infecté exfiltre un fichier clients caché dans des requêtes DNS.", build(c) { noise(c, 10); dnsTunnel(c); noise(c, 10); } },
    normal: { label: 'Trafic normal', desc: 'Une journée calme : navigation, intranet, partage de fichiers, SSH légitime.', build(c) { noise(c, 80); sshLegit(c); noise(c, 30); } }
  };

  function buildSample(key) {
    let seed = 7;
    for (const ch of key) seed = (seed * 31 + ch.charCodeAt(0)) | 0;
    const c = new Cap(seed);
    SAMPLES[key].build(c);
    return c.toPcap();
  }

  Object.assign(PL, { SAMPLES, buildSample });
})(typeof window !== 'undefined' ? window : globalThis);
