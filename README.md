# README #

Wifite is a python script which automates the WEP and WPA cracking process with aircrack-ng tools.

Please Note: **Wifite can and will delete certain existing .CAP and .XOR files inside of the directory it is run**; specifically any `*`.XOR files and replay-`*`.cap files. Please move wifite.py into its own directory to avoid the deleting of these kinds of files.

Wifite requires:

  * A Linux operating system
    * I highly recommend using the [Backtrack4 R1](http://www.backtrack-linux.org/downloads/) flavor of Ubuntu. It already contains many tools required by wifite, and wifite was developed on this platform.
    * Other recommended distributions of linux include ArchLinux, Auditor, and Bauer-Puntu.
  * Wireless drivers patched for injection and monitor mode,
    * To find out if there exist linux drivers for your wireless chipset, [see this aircrack-ng site](http://www.aircrack-ng.org/doku.php?id=compatibility_drivers)
    * Sometimes the easiest thing to do is buy a new wireless card that already has drivers available.
  * The aircrack-ng suite of tools
    * v1.1 is PREFERRED
    * you need at LEAST v1.0-rc4, but please upgrade to the latest v1.1
  * Python 2.4.5 or 2.5.2
    * other versions may work, but these are the only confirmed working versions


# Before using Wifite #

Before you run wifite, please learn and use the command-line tools available with aircrack-ng. [Here is an easy guide to WEP cracking](http://www.aircrack-ng.org/doku.php?id=simple_wep_crack) and [here is an easy guide to WPA cracking](http://www.aircrack-ng.org/doku.php?id=cracking_wpa).
Only after you have tested and successfully cracked WEP and WPA without the use of an automated tool should you use Wifite.
This is for two reasons:
  1. If it doesn't work, you blame Wifite.
    * Sometimes you have the wrong wireless drivers, an outdated version of aircrack-ng, or are missing important tools
  1. When it does work, you actually know what it is doing.
    * Don't be a script kiddie.  Understand the process being WEP and WPA cracking. I wrote this script for myself because remembering the aircrack-ng commands can be frustrating. Don't let this script enable you to be a script kiddie!