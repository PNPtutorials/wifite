# introduction #

Conçu pour Backtrack4 [R1](https://code.google.com/p/wifite/source/detail?r=1) ou Ubuntu. Uniquement pour Linux, aucun support pour WIndows ou OSX.

# purpose #

Attaquer plusieurs réseaux crypté WEP et WPA en meme temps. Cet outil est personalisable avec quelques options. Le tout automatique.

# features #

  * Programme disponible en Anglais et en Français
  * Trie les cibles par puissances (en dB), il va cracker le réseau le plus proche en premier.
  * Déconnecte automatiquement (deauth) les clients des réseaux cachés (pour un channel fixe)
  * De nombreux filtres pour choisir quoi attaquer (Wep/Wpa/Les deux, Channels, la puissance du signal, etc)
  * Options personalisables (Timeouts, Paquets/sec, Channels, Changer l'adresse MAC, Ignorer la fake-auth, etc)
  * Tout les handshakes WPA sont sauvés dans le même répertoire que wifite.py
  * Deauthentication WPA intelligente
  * Stoppez n'importe quel le attaque avec Ctrl+C (+ Option: continuer, attaquez la prochaine cible ou quittez)
  * Changez d'attaque WEP sans reinitialiser les IVs
  * Support de la fake-auth pour le chipset intel 4965
  * Support SKA (Pas testé)
  * Montre le résultat de la session a la fin et montre toutes les clé crackées
  * Tout les mots de passes sont sauvés dans le log.txt
  * Mettez a jour wifite: ./wifite.py -upgrade

# execution #

Télechargez la dernière version:
```
wget -O wifite.py http://wifite.googlecode.com/svn/trunk/fr/wifite_fr.py
```
Changez les permissions pour le rendre exécutable:
```
chmod +x wifite.py
```
executez:
```
python wifite.py
```
Ou affichez l'aide
```
python wifite.py -help
```