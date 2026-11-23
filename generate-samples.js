// Régénère les captures d'exemple du dossier samples/ : node tools/generate-samples.js
const fs = require('fs'), path = require('path');
require('../js/samples.js');
const out = path.join(__dirname, '..', 'samples');
fs.mkdirSync(out, { recursive: true });
for (const key of Object.keys(PL.SAMPLES)) {
  const file = path.join(out, key + '.pcap');
  fs.writeFileSync(file, PL.buildSample(key));
  console.log(file, fs.statSync(file).size, 'octets');
}
