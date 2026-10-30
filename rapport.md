# Rapport — Analyse des journaux du pare-feu

## Résumé
Après nettoyage (60 doublons supprimés, casse des protocoles uniformisée, 166 valeurs
manquantes de `bytes_sent` remplacées par la médiane), il reste 5 440 connexions sur une
semaine. Le trafic est dominé par HTTPS (port 443) et 13,57 % des connexions sont bloquées
(DENY). Deux comportements sortent clairement du lot : un balayage de ports par un PC et un
volume d'octets anormal envoyé par une caméra IoT.

## Comportement suspect 1 — Scan de ports (192.168.1.99)
- Ce PC a contacté **328 ports distincts** ; les autres machines en contactent 8 au maximum.
- Il a généré 400 connexions, dont **383 bloquées (DENY)**, toutes entre 00:00 et 00:15 le 2026-10-08.
- Interprétation : un hôte interne qui teste beaucoup de ports en peu de temps est typique d'une
  reconnaissance (machine compromise ou utilisateur malveillant).

## Comportement suspect 2 — Exfiltration de données (192.168.1.11)
- Cette caméra IoT a envoyé **≈ 260 millions d'octets** ; la suivante, environ 0,6 million.
- 38 connexions vers 8.8.8.8, toutes **autorisées (ALLOW)** le 2026-10-10, représentent 99,8 % de ce volume.
- Interprétation : une caméra envoie normalement peu de données (≈ 3 ko par connexion ici). Un tel
  volume vers l'extérieur suggère un vol de données ou un appareil compromis.

## Recommandations
1. **Isoler 192.168.1.99** et analyser ce poste ; ajouter une règle de pare-feu qui bloque
   et alerte quand une même source tente de nombreux ports en peu de temps.
2. **Segmenter les objets IoT** dans un VLAN dédié, avec autorisation uniquement vers les serveurs
   dont ils ont besoin, et limiter leur trafic sortant vers Internet.
3. **Fermer Telnet (port 23)**, protocole non chiffré (74 tentatives bloquées vues ici), et
   privilégier SSH.
4. Mettre en place une alerte sur les volumes sortants anormaux par appareil.
