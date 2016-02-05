# Newest version available on GitHub #

Get the latest version at [github.com/derv82/wifite](https://github.com/derv82/wifite)

What's new in this version:
  * support for cracking WPS-encrypted networks (via reaver)
  * 2 new WEP attacks
  * more accurate WPA handshake capture
  * various bug fixes

Version 2 does not include a GUI, so everything must be done at the command-line.

# Mention in the New York Times #
Wifite was mentioned in the New York Times' article "New Hacking Tools Pose Bigger Threats to Wi-Fi Users" from February 16, 2011. [Here is a link to the article.](http://www.nytimes.com/2011/02/17/technology/personaltech/17basics.html)

# Introduction #
Designed and tested on Linux; works with Backtrack 5, [BlackBuntu](http://www.blackbuntu.com/), [BackBox](http://www.backbox.org/), and [Pentoo](http://www.pentoo.ch)! Linux only; no windows or OSX support (but you're welcome to try).

# Purpose #
To attack multiple WEP, WPA, and WPS encrypted networks in a row.  This tool is customizable to be automated with only a few arguments.  Wifite aims to be the "set it and forget it" wireless auditing tool.


# Features #
  * sorts targets by signal strength (in dB); cracks closest access points first
  * automatically de-authenticates clients of hidden networks to reveal SSIDs
  * numerous filters to specify exactly what to attack (wep/wpa/both, above certain signal strengths, channels, etc)
  * customizable settings (timeouts, packets/sec, etc)
  * "anonymous" feature; changes MAC to a random address before attacking, then changes back when attacks are complete
  * all captured WPA handshakes are backed up to wifite.py's current directory
  * smart WPA de-authentication; cycles between all clients and broadcast deauths
  * stop any attack with Ctrl+C, with options to continue, move onto next target, skip to cracking, or exit
  * displays session summary at exit; shows any cracked keys
  * all passwords saved to cracked.txt
  * built-in updater: `./wifite.py -upgrade`

# Requirements #
  * linux operating system (confirmed working on Backtrack 5, BackBox, BlackBuntu, Pentoo, Ubuntu 8.10 (BT4R1), Ubuntu 10.04, Debian 6, Fedora 16)
  * tested working with **python 2.6.x**, and **python 2.7.x**,
  * wireless drivers patched for monitor mode and injection. Most security distributions (Backtrack, BlackBuntu, etc) come with wireless drivers pre-patched,
  * aircrack-ng (v1.1) suite: available via apt: _apt-get install aircrack-ng_ or [at the aircrack-ng website](http://www.aircrack-ng.org/install.html),

# Suggested applications #
  * [reaver](http://code.google.com/p/reaver-wps), for attacking WPS-encrypted networks
  * pyrit, cowpatty, tshark: not required, but help verify WPA handshake captures

_For help installing any of these programs, [see the installation guide (hosted on github)](https://github.com/derv82/wifite/wiki/Installation)_

# Execution #
download the latest version:
```
wget -O wifite.py https://github.com/derv82/wifite/raw/master/wifite.py
```
change permissions to executable:
```
chmod +x wifite.py
```
execute:
```
python wifite.py
```
or, to see a list of commands with info:
```
./wifite.py -help
```


# Screenshots #

successful WEP attack (after 90 seconds):

![http://wifite.googlecode.com/files/screenshot_wep.png](http://wifite.googlecode.com/files/screenshot_wep.png)


successful WPS attacks (after 17 hours):

![http://wifite.googlecode.com/files/screenshot_wps.png](http://wifite.googlecode.com/files/screenshot_wps.png)

# Video Tutorial #

(tutorial is for v1 of wifite.)

capturing WPA handshake using Wifite (and then cracking with oclHashCat).

<a href='http://www.youtube.com/watch?feature=player_embedded&v=eRKLHqXr33I' target='_blank'><img src='http://img.youtube.com/vi/eRKLHqXr33I/0.jpg' width='425' height=344 /></a>

video credit: [Maurizio Schmidt](http://maurisdump.blogspot.com/)

# Examples #

_the program contains lots of interactivity (waits for user input). these command-line options are meant to make the program 100% automated -- no supervision required._

to crack all WEP access points:
```
./wifite.py -all -wep
```

to crack all WPS access points with signal strength greater than (or equal to) 50dB:
```
./wifite.py -p 50 -wps
```

to attack all access points, use 'darkc0de.lst' for cracking WPA handshakes:
```
./wifite.py -all --dict /pentest/passwords/wordlists/darkc0de.lst
```
to attack all WPA access points, but do not try to crack -- any captured handshakes are saved automatically:
```
./wifite.py -all -wpa --dict none
```

to crack all WEP access points greater than 50dB in strength, giving 5 minutes for each WEP attack method, and send packets at 600 packets/sec:
```
./wifite.py --pow 50 -wept 300 -pps 600
```

to attempt to crack WEP-encrypted access point "2WIRE752" _endlessly_ -- program will not stop until key is cracked or user interrrupts with ctrl+C):
```
./wifite.py -e "2WIRE752" -wept 0
```

# Donations #

If you wish to donate to this project, I ask that you donate **instead** to [the aircrack-ng team](http://www.aircrack-ng.org/) or you could buy something from [Tactical Network Solutions](http://www.tacnetsol.com/products). These are the teams which produced the awesome open-source software that wifite depends on.  Wifite would not exist if not for these amazing tools.