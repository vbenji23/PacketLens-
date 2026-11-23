// Assemble src/index.html + css/ + js/ en un seul fichier index.html autonome : node tools/build.js
// Un seul fichier = le site marche partout (double-clic, GitHub Pages, aperçu en ligne), sans dépendre de chemins relatifs.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
let html = fs.readFileSync(path.join(root, 'src', 'index.html'), 'utf8');
html = html.replace(/<link rel="stylesheet" href="(css\/[^"]+)">/g, (_, f) =>
  '<style>\n' + fs.readFileSync(path.join(root, f), 'utf8') + '\n</style>');
html = html.replace(/<script src="(js\/[^"]+)"><\/script>/g, (_, f) =>
  '<script>\n' + fs.readFileSync(path.join(root, f), 'utf8').replace(/<\/script/gi, '<\\/script') + '\n</script>');
fs.writeFileSync(path.join(root, 'index.html'), html);
console.log('index.html généré :', html.length, 'caractères');
