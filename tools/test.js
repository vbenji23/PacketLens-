// Vérifie que chaque capture d'exemple déclenche exactement les alertes attendues : node tools/test.js
const fs = require('fs'), path = require('path');
for (const f of ['pcap', 'detect', 'samples']) require('../js/' + f + '.js');
const expected = {
  incident: ['arpsweep', 'scan', 'brute', 'brute', 'creds', 'arpspoof', 'creds', 'creds', 'dnstunnel'],
  scan: ['arpsweep', 'scan'],
  brute: ['brute', 'brute'],
  arp: ['arpspoof', 'creds', 'creds'],
  dns: ['dnstunnel'],
  normal: []
};
let fail = 0;
for (const key of Object.keys(expected)) {
  const file = path.join(__dirname, '..', 'samples', key + '.pcap');
  const buf = fs.existsSync(file) ? fs.readFileSync(file) : PL.buildSample(key);
  const A = PL.analyze(PL.readCapture(new Uint8Array(buf)));
  const got = A.alerts.map(a => a.type);
  const ok = JSON.stringify(got) === JSON.stringify(expected[key]);
  if (!ok) fail++;
  console.log(`${ok ? 'OK  ' : 'ÉCHEC'} ${key.padEnd(9)} ${A.pk.length} paquets, ${A.protos.map(p => p.join(':')).join(' ')}`);
  for (const a of A.alerts) console.log(`      #${a.n} [${a.sev}] ${a.title} — ${a.src} → ${a.dst}\n         ${a.detail}`);
  if (!ok) console.log('      attendu :', expected[key].join(', '));
}
process.exit(fail ? 1 : 0);
