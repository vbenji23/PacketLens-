# PacketLens

**Analyseur de captures réseau (PCAP) qui tourne entièrement dans le navigateur.**

On dépose un fichier `.pcap` ou `.pcapng` (Wireshark, tcpdump). PacketLens décode les paquets octet par octet, reconstitue la chronologie et la carte des échanges, puis détecte automatiquement les attaques réseau classiques. Le fichier n'est envoyé à aucun serveur.

> Projet portfolio cybersécurité, Benjamin Vincenti, Guardia Cyber School.

## Fonctionnalités

- **Lecture des formats PCAP et PCAPNG** codée à la main, sans bibliothèque : en-têtes globaux, blocs pcapng (SHB, IDB, EPB, SPB), horodatage en micro et nanosecondes, petit et grand boutisme.
- **Décodage des protocoles** : Ethernet (avec VLAN), Linux cooked, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, FTP, SSH (bannières), TLS (nom du site via le SNI), SMB, Telnet.
- **Chronologie** : volume de paquets dans le temps, avec une bande par alerte pour rejouer l'attaque étape par étape.
- **Carte des échanges** : graphe des machines et de leurs conversations, avec le rôle de chacune (attaquant, cible, machine compromise).
- **Fiche machine** : adresses MAC, volume, protocoles, ports contactés, alertes liées.
- **Table des paquets** : recherche plein texte, filtre « suspects seulement », filtre par alerte.
- **Rapport JSON** exportable, avec les références MITRE ATT&CK, pour l'envoyer vers un SIEM.

## Détections

| Règle | Ce qui la déclenche | Gravité | MITRE ATT&CK |
|---|---|---|---|
| Scan de ports | Une IP envoie des SYN vers au moins 20 ports différents d'une même machine en moins de 10 min. Les ports ouverts trouvés (SYN-ACK) sont listés. | Élevée | T1046 |
| Balayage ARP | Une machine demande l'adresse MAC d'au moins 20 IP en moins de 2 min. | Moyenne | T1018 |
| Ping sweep | Des pings vers au moins 10 machines différentes en moins de 5 min. | Moyenne | T1018 |
| Brute force (SSH, RDP, FTP, Telnet, bases de données…) | Au moins 10 connexions vers un service d'authentification en moins de 15 min. Le client SSH utilisé est signalé s'il trahit un outil d'attaque (libssh2, paramiko…). | Élevée | T1110 |
| Brute force FTP | Au moins 5 réponses « 530 ». Critique si une connexion finit par réussir (code 230). | Élevée ou critique | T1110.001 |
| Identifiants en clair | En-tête HTTP `Authorization: Basic`, formulaire HTTP avec un champ mot de passe, commandes FTP `USER`/`PASS` réussies. Le mot de passe est masqué à l'affichage. | Élevée | T1552 |
| ARP spoofing | Une même IP revendiquée par plusieurs adresses MAC. La MAC suspecte est celle qui revendique plusieurs IP ou envoie des réponses ARP non sollicitées. Le nombre de paquets détournés est calculé. | Critique | T1557.002 |
| Tunnel DNS | Au moins 15 sous-domaines uniques d'un même domaine, longs (25 caractères en moyenne ou blocs de 40+) et aléatoires (entropie de Shannon ≥ 3,5 bits par caractère). Le volume exfiltré est estimé. | Élevée | T1071.004 |

## Utilisation

Aucune installation : `index.html` est un fichier unique qui contient tout (HTML, CSS, JavaScript). Double-cliquez dessus pour l'ouvrir dans un navigateur, ou publiez le dossier avec **GitHub Pages** (Settings → Pages → branche `main`, dossier racine).

Six captures d'exemple sont intégrées (boutons en haut de la page) et disponibles dans `samples/` pour les ouvrir aussi dans Wireshark :

| Fichier | Scénario | Alertes attendues |
|---|---|---|
| `incident.pcap` | Matinée complète : reconnaissance, scan, brute force SSH et FTP, ARP spoofing, vol d'identifiants, exfiltration DNS | 9 |
| `scan.pcap` | Balayage ARP puis scan SYN du serveur | 2 |
| `brute.pcap` | Hydra contre SSH, puis brute force FTP réussi | 2 |
| `arp.pcap` | Homme du milieu par empoisonnement ARP, mots de passe interceptés | 3 |
| `dns.pcap` | Poste infecté qui exfiltre un fichier clients par DNS | 1 |
| `normal.pcap` | Journée calme, pour vérifier l'absence de faux positifs | 0 |

Ces captures sont **générées par du code** (`js/samples.js`) : adresses privées ou réservées à la documentation (RFC 5737), domaines `.example`, comptes inventés. Aucune donnée réelle.

### Faire ses propres captures (dans un labo à soi)

Dans des machines virtuelles isolées (par exemple Kali + Metasploitable), lancez une capture puis l'attaque :

```bash
sudo tcpdump -i eth0 -w ma-capture.pcap        # capture
nmap -sS 192.168.56.101                         # scan SYN
hydra -l admin -P rockyou.txt ssh://192.168.56.101
sudo arpspoof -i eth0 -t 192.168.56.101 192.168.56.1
```

N'analysez et n'attaquez que des machines et des réseaux dont vous avez l'autorisation.

## Architecture

```
index.html            le site complet en un seul fichier (généré, à ne pas modifier à la main)
src/index.html        structure de la page (source)
css/style.css         mise en forme
js/pcap.js            lecture PCAP/PCAPNG et décodage des protocoles
js/detect.js          statistiques et règles de détection
js/samples.js         générateur de captures d'exemple (vrais fichiers .pcap)
js/app.js             interface : chronologie, carte, alertes, tableaux
tools/test.js         tests : chaque capture doit donner exactement les alertes attendues
tools/generate-samples.js   régénère le dossier samples/
tools/build.js        assemble src/, css/ et js/ dans index.html
```

Après une modification dans `src/`, `css/` ou `js/`, régénérez le site :

```bash
node tools/build.js
```

Tests (Node.js 18 ou plus) :

```bash
node tools/test.js
```

## Sécurité de l'outil lui-même

Un fichier de capture est une donnée non fiable : un attaquant peut glisser du HTML ou du JavaScript dans une requête HTTP ou un nom DNS. Tout texte issu de la capture est donc échappé avant affichage, pour éviter les failles XSS. Les mots de passe détectés sont masqués. Rien ne quitte le navigateur.

## Limites

- Pas de réassemblage des flux TCP : une requête HTTP découpée en plusieurs paquets n'est analysée que sur son premier segment.
- Les seuils des règles sont fixes. Un trafic légitime très intense (supervision, scanner de vulnérabilités autorisé) peut déclencher des alertes.
- Les gros fichiers (plusieurs centaines de Mo) sont limités par la mémoire du navigateur.

## Pistes d'amélioration

- Réassemblage TCP et extraction des fichiers transférés.
- Seuils réglables depuis l'interface.
- Envoi des alertes vers le mini-SIEM WatchTower.
- Détection des beacons de C2 (connexions à intervalle régulier).

## Licence

MIT
