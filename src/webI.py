'''
	Submoudule - Web Interface
	Test all the most common problems with Web Interfaces in IoT
'''
# python C:\Python27\Tools\i18n\pygettext.py -d webI webI.py
# inurl:"index.php?cat_id="
# To-do:	- Implement CSRF
#			- SQLi with Mechanize
# 			- Any bug corrections

#!/usr/bin/python
from __future__ import absolute_import
import re, sys, gettext, requests, socket, ssl, urllib2, urllib3, BeautifulSoup, mechanize
from crawler import Crawler, CrawlerCache

#Utils Functions
from utils import buildResponse
from utils import clear
from utils import printLine
from utils import bcolors
from utils import getLoginPage
from utils import pause
from urlparse import urlparse

# Scapy Functions
from scapy.all import ICMP
from scapy.all import IP
from scapy.all import RandShort
from scapy.all import sr1
from scapy.all import TCP

# Just for temporary tests
possibleParam = ['cat_id','id','page','pgID','pg','pageid','name','user','userN','uName','userId','UserId','uPass','password',
'passwd','pass','option','file','cat','category','text']

# HTTP Code definitions
status_code = {	200: ' OK',
				404: ' Not Found',
				301: ' Moved Permanently',
				302: ' Moved Temporarily',
				303: ' Resource moved to another URL (HTTP 1.1)',
				500: ' Server Error'				
}

'''
	Detect if there is any Web Application Firewall being used...
	Use an ACK scanning. This is especially good when attempting to probe for the existence 
	of a firewall and its rulesets. Simple packet filtering will allow established connections 
	(packets with the ACK bit set), whereas a more sophisticated stateful firewall might not.
'''
def detectWAF(url,port,lang):
	import logging
	
	noWAF = _("\nWeb Application Firewall nao detectado")
	thereIsWAF = _("\nWeb Application Firewall detectado")

	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	
	parsed = urlparse(url)
	if len(parsed.netloc) == 0:
		parsed = urlparse('http://'+url)
		pass
	
	dst_ip = socket.gethostbyname(parsed.netloc)
	src_port = RandShort()


	# A TCP packet with the ACK flag (16) set and the port number to connect to is send to the server. 
	ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=port,flags="A"),timeout=10, verbose=0)

	# 
	if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
		return _('Resposta: ') + "<No_Response_to_TCP_ACK>" + buildResponse(True, thereIsWAF,_('\n'))
	# If the server responds with the RST flag set inside a TCP packet, then the port is unfiltered and a stateful firewall is absent.
	elif(ack_flag_scan_resp.haslayer(TCP)):
		if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4): # RST flag = 4
			return _('Resposta: ') + "<RST_flag_SET>" + buildResponse(False, _('\n'),noWAF) # RST flag
	# If the server doesnt respond to our TCK ACK scan packet or if it responds with a TCP packet with ICMP type 3 or code 1, 2, 3, 9, 10, or 13 set,
	# then the port is filtered and a stateful firewall is present.
	elif(ack_flag_scan_resp.haslayer(ICMP)):
		if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return _('Resposta: ') + "<ICMP_type_3_TCP_Packet>" + buildResponse(True, thereIsWAF,_('\n'))

'''
	Detect if there is any Web Application Firewall being used  - Deprecated
'''
def detectWAF2(url,lang):
	maliciousRequest = mechanize.Browser()
	maliciousRequest.set_handle_robots(False)
	maliciousRequest.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
	noWAF = "No WAF detected"
	thereIsWAF = "WAF detected"
	headersChange = "Headers Changed" # to a possible improvement

	#request = urllib2.Request("https://"+url, headers=hdr)
	maliciousRequest.open("http://"+url)
	
	crossSiteScriptingPayLoad = "<svg><script>alert&grave;1&grave;<p>"

	currentForm = 0
	for form in maliciousRequest.forms():
		maliciousRequest.select_form(nr = currentForm)

		# get all the possible SelectControls
		TextControls = getTextControls(str(maliciousRequest.form))
		if len(TextControls)==0:
			controlT = raw_input(_('Nao ha inputs para teste de Firewall\n'))
		for x in TextControls:
			try:
				# Test if the object is read only or none type (not present)
				maliciousRequest.form[x] = crossSiteScriptingPayLoad
				try:
					maliciousRequest.submit()
					pass
				except (mechanize.HTTPError,urllib2.HTTPError) as e:
					pass
			except (mechanize._form.AmbiguityError, TypeError,ValueError) as e:
				pass			
			sourceCode =  maliciousRequest.response().read()

			# Search for a message block from a Firewall
			if sourceCode.find('WebKnight') >= 0:
				return _('Resposta: ') + thereIsWAF + buildResponse(True, _('Firewall: WebKnight'),_(''))
			elif sourceCode.find('Mod_Security') >= 0:
				return _('Resposta: ') + thereIsWAF + buildResponse(True, _('Firewall: Mod Security'),_(''))
			elif sourceCode.find('Mod_Security') >= 0:
				return _('Resposta: ') + thereIsWAF + buildResponse(True, _('Firewall: Mod Security'),_(''))
			elif sourceCode.find('dotDefender') >= 0:
				return _('Resposta: ') + thereIsWAF + buildResponse(True, _('Firewall: Dot Defender'),_(''))
			elif (sourceCode.find('firewall') >= 0) | (sourceCode.find('Firewall') >= 0) | (sourceCode.find('WAF') >= 0):
				return _('Resposta: ') + thereIsWAF + buildResponse(True, _('Firewall is present'),_(''))
			
		## 
		# Test the nest
		currentForm += 1
	
	# Build the response
	return _('Resposta: ') + noWAF + buildResponse(False, _('\n'),_('\nFirewall nao detectado'))

'''
	Search for the Login Pages with common names
'''
def getLoginPages(url,lang):
	loginT = getLoginPage(url,lang) # = (msg,pageFound,pageList)
	response = _('Resposta: ') + loginT['msg'] + buildResponse(loginT['pageFound']==0, _('\nPaginas de Login OK'),_('\n[+] Paginas de Login contem url comum:'))
	
	# Including found urls ins the response. 
	# This runs in O(n) because CPython extends the string in the place
	for x in loginT['pageList']:
	 	response += '\n[|]\t' + x 
	 	pass 
	return (response,loginT['pageList'])

'''
	Get all field names on the given source code
'''
def getParams(htmlText):

	# Search the 'name="' string on the page code to get the name of all fields
	textBox = 'name='
	delimiter = '\"'
	
	fieldPos = [m.start() for m in re.finditer(textBox+delimiter, htmlText)]
	if len(fieldPos) == 0:
		delimiter = "\'"
		fieldPos = [m.start() for m in re.finditer(textBox+delimiter, htmlText)]

	namePos = [x+6 for x in fieldPos]
	params = []

	# With the index of all names, copy them to a list 
	for index in namePos:
		paramName =  htmlText[index:]
		paramName = paramName.split(delimiter,1)[0]
		if not paramName in params:
			params.append(paramName)
	return params

'''
	Get all field names on the given source code
'''
def getTextControls(htmlText):

	# Search the 'TextControl' string on the page code to get the name of all fields
	textBox = 'TextControl'
	delimiter = '='
	fieldPos = [m.start() for m in re.finditer(textBox, htmlText)]
	namePos = [x+12 for x in fieldPos]
	params = []

	# With the index of all Text Controls, copy them to a list 
	for index in namePos:
		paramName =  htmlText[index:]
		paramName = paramName.split(delimiter,1)[0]
		if not paramName in params:
			params.append(paramName)
	return params

'''
	Show information about the local network
'''
def showInf(lang):
	import netifaces
	clear()
	print (_("Interfaces"))
	def_gw_device = netifaces.gateways()['default'][netifaces.AF_INET][1]
	print def_gw_device
	macaddr = netifaces.ifaddresses('enp0s25')[netifaces.AF_LINK][0]['addr']
	print macaddr
	pause()

'''
	Try a SQL Injection Attack on the given url+path with the given string and parameters
'''
def sqli(url,path,param,stringInj):
	import urllib2
	
	# To avoid some certificate errors
	hdr = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

	# Improving: Do requests trying combinations of the params. IPC: Try to guess the password field and apply the sqli on it
	'''result = requests.get(targetURL)
				print result.status_code'''
	
	# Try to to a GET on the url with the string on the parameter
	respT = urllib2.Request('http://'+ url + path + '?' + param + '=' + stringInj, headers=hdr)
	resp = urllib2.urlopen(respT)
	body = resp.read()

	# Must ignore errors if the codification of the text is wrong (indicates that the attack did not work)
	fullbody = body.decode(u'utf-8', errors='ignore') 
	return ("You have an error in your SQL syntax" in fullbody)

'''
	Test the use of https in the web interface
'''
def testHttps(url,lang):
	global socket, requests, status_code, ssl
	try:
		r = requests.get('https://'+url)
		response = _('Resposta: ') + str(r) + buildResponse(str(r) == '<Response [200]>', _('\nHttps OK'),_('\nHttps nao utilizado'))
		pass
	except requests.exceptions.SSLError as e:
		err = str(e.message)
		if '[' in err:
			err = err.split("[",1)[1]
			err = err.split("]",1)[0]
		response = _('Resposta: ') + err + buildResponse(False, '',_('\nHttps nao utilizado'))
		pass
	return response

'''
	Test the use of https in the web interface
'''
def testClickJack(url,lang):
	# Read the return of a "GET" request
	r = requests.get('http://'+url)
	validation = ('X-Frame-Options' in r.headers)

	# Search for the presence of the 'X-Frame-Options' on the header returned and analyse the value
	if validation == True:
		validation = (r.headers['X-Frame-Options'] == 'DENY') | (r.headers['X-Frame-Options'] == 'SAMEORIGIN')
	response = _('Resposta: ') + str(r) + buildResponse(validation,_('\nX-Frame-Options OK'),_('\nX-Frame-Options nao configurada'))

	return response

'''
	Test the SQLi attacks on the given paths
'''
def testSQLi(url,paths,lang):
	import socket, sys, requests
		
	# Set the local and global variables
	global status_code
	print url
	pageList = []
	msg = ["Nao foram encontrados indicios de um DBMS no codigo","O teste gerou um acesso indevido ao banco de dados"]
	msgIndex = 0;
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	# Build a test for each url received
	for urlTest in paths:
		hdr = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
		if url in urlTest:
			urlTest = urlTest.split(url,1)[1]
			pass
		# Try to reach the url to know if there is a page tp test
		try:
			# Do the request
			response = requests.get('http://'+url+urlTest)
		except (requests.exceptions.SSLError, socket.error) as e:
			response = requests.get('http://'+url+urlTest, verify=False)

		sourceCode = response.content

		# Tests if the page is there and try to do a SQL Injection attack
		if response.status_code == 200:
			# Read the source code and get each field name to try an attack on it
			params = getParams(response.content)
			print _('Testando '+ bcolors.UNDERLINE + urlTest +  bcolors.ENDC + ' - Campos: ' + ' '.join(str(p) for p in params) )
			# Test a SQL Injection on each of the fields in the page source
			for param in params:
				# Try to access the url modifying the fields sent
				try:
					if (sqli(url,urlTest,param,"1\' or \'1\' = \'1") | sqli(url,urlTest,param,'1\" or \"1\" = \"1')):
						msgIndex = 1
						pageList.append(urlTest)
				except urllib2.HTTPError, e: # Access forbidden
					continue
		response.close()

	response =  _('Resposta: ') + msg[msgIndex] + buildResponse(msgIndex==0, _('\nTratamento de SQL Injection OK - Verificar arquivo de saida'),_('\n[+] Paginas vulneraveis a SQL Injection:'))
	for page in pageList:
	 	response += '\n[|]\t' + bcolors.UNDERLINE + page +  bcolors.ENDC 
	 	pass 
	return response

'''
	Test the XSS attack on the website
'''
def testXSS(url,lang):
	crawler = Crawler(CrawlerCache('crawler.db'))
	root_re = re.compile('^/$').match

	# Important declarations
	paths = ["/"]
	usedStrings = []
	selection = 3
	pageList = []
	msg = ["Website is not XSS vulnerable","XSS Vulnerability Found with: "]
	msgIndex = 0
	testAt = (False,"")

	# Map website structure
	while (selection != 1) & (selection != 2):
		selection = int(raw_input(_('Escolha um metodo: \n1 - Inserir os caminhos manualmente\n2 - Buscar os caminhos recursivamente (pode demorar)\n')))
	
	# Append the entire Recursive Search to the end of the paths list
	if selection == 2:
		paths = set(paths + crawler.crawl('http://'+url, no_cache=root_re))

	# Input method
	while selection == 1:
		path = raw_input(_('Insira um caminho iniciando por /: '))
		if not path in paths:
			paths.append(path)
			pass
		selection = raw_input(_('Deseja inserir mais caminhos? \n1 - Sim\n2 - Nao\n'))
	
	# Testing XSS vulnerabilites on every path
	for path in paths:
		print _('Testando ') + bcolors.UNDERLINE + path +  bcolors.ENDC
		testAt = xss('http://'+ str(url) + path)
		if testAt[0] == True:
			msgIndex = 1
			pageList.append(path)
			if not testAt[1] in usedStrings:
				msg[1] = msg[1] + testAt[1]
				usedStrings.append(testAt[1])
	
	# Making the result
	response =  _('Resposta: ') + msg[msgIndex] + buildResponse(msgIndex==0, _('\nTratamento de XSS OK'),_('\n[+] Paginas vulneraveis XSS:'))
	for x in pageList:
	 	response += '\n[|]\t' + x 
	 	pass 
	return response

'''
	Do all the Web Interface Tests
'''
def webIDirect(lang):
	global status_code
	removedSlash = False

	# Try to connect to the website
	url = raw_input(_("Endereco da interface para teste (com a porta): "))
	parsed = urlparse(url)
	if len(parsed.netloc) == 0:
		parsed = urlparse('http://'+url)
		pass

	url = url.replace("http://","")
	url = url.replace("https://","")
	try:
		# Do the request
		req = requests.get('http://'+url, stream=True)
		# FROMFD ERROR s = socket.fromfd(req.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
		clear()
		print _("[!] Interface esta online.")
		if not (':' in url):
			port = 80
		else:
			port = int(parsed.port)
	except (requests.ConnectionError, socket.error) as Exit:
		wait = raw_input(_('Interface Offline ou URL Invalida'))
		return
	
	# Remove the / end marker
	if url.endswith('/'):
		removedSlash = True
		url = url[:-1]
		pass
	
	# Show the Url on the top of the page
	print url

	# Get the information from socket
	# FROMFD ERROR port = s.getpeername()[1]
	
	# Show the test basic information
	print _('- Hora:\t\t') + req.headers['Date']
	
	# Get the target hostname information (IP, Port, Server )
	if ':' in url:
		ipAddr = socket.gethostbyname(url.split(":",1)[0])
	else:
		ipAddr = socket.gethostbyname(parsed.netloc)

	print _('- IP:\t\t') + ipAddr
	if url.find('/') != -1:
		hostname = url[:-(len(url)-url.find('/'))]
	else:
		hostname = url
	print _('- Hostname:\t') + hostname
	try:
		serv = socket.getservbyport(port)
	except socket.error as e:
		serv = "Nao padrao"
	print _('- Porta:\t') + str(port) + ' [' +serv + ']'
	if 'Server' in req.headers:
		print _('- Servidor:\t') + req.headers['Server']
	
	############# DEBUG AREA

	# Debbuging vulnerabilities


	############# END OF DEBUG 

	# [1] Testing Https use
	printLine()
	print bcolors.HEADER + '[1] ' + bcolors.ENDC + (_('Uso de HTTPS'))
	print testHttps(url,lang)
	
	# [2] Testing Protection against Clickjack/UI Redress
	printLine()
	print bcolors.HEADER + '[2] ' + bcolors.ENDC + (_('Protecao contra Clickjack/UI Redress'))
	print testClickJack(url,lang)

	# [3] Testing if the login or admin pages can be easily found
	printLine()
	print bcolors.HEADER + '[3] ' + bcolors.ENDC + (_('Paginas de Login e Admin'))
	possibleUrlResponse = getLoginPages(url, lang)
	print possibleUrlResponse[0]

	# [4] Testing SQLi attack
	printLine()
	print bcolors.HEADER + '[4] ' + bcolors.ENDC + (_('SQL Injection'))
	possibleUrlResponse[1].insert(0,"/")
	exitOpt = raw_input(_('Deseja incluir algum caminho para teste?:\n1 - Sim\n2 - Nao\n'))
	if ((exitOpt != 1) & (len(possibleUrlResponse[1]) == 1)):
		print _('Url de formulario explicito nao encontrada')
	while exitOpt == 1:
		possibleUrl = raw_input(_('Insira um caminho para testar: '))
		possibleUrlResponse[1].append(possibleUrl)
		exitOpt = raw_input(_('Deseja incluir mais algum teste?:\n1 - Sim\n2 - Nao\n'))
		pass
	if len(possibleUrlResponse[1]) != 0:
		print testSQLi(url,possibleUrlResponse[1],lang)

	# [5] Testing XSS vulnerabilities
	printLine()
	print bcolors.HEADER + '[5] ' + bcolors.ENDC + (_('XSS - Cross-site Scripting'))
	print testXSS(url, lang)

	# [6] Testing if there is a Web Application Firewall
	printLine()
	print bcolors.HEADER + '[6] ' + bcolors.ENDC + (_('Web Application Firewall'))
	print detectWAF(ipAddr,port,lang)
	pause()

	pass

'''
	Get the Web Interface Url and do all the tests 
'''
def webIMenu(lang):	
	# Change the software language 
	import gettext
	global _
	if lang == 'pt':
		_ = lambda s: s
	else:
		lg = gettext.translation('webI', localedir='locale', languages=[lang])
		lg.install()
		_ = lg.gettext
	
	# Basic definitions for the module menu
	menuOpts = {0:'0',1:'showInf',2:'webIDirect'}

	# Web Interface Menu
	subModule = {	'showInf':showInf, 	# Close the program
					'webIDirect':webIDirect, 		# Submodule of Web Interface tests
					}
	# Menu of the module
	while True:
		# Clean the screen
		clear()
		
		# Show the menu
		print(_('Web Interface Pentest'))
		opt = int(raw_input(_("0 - Voltar para o Menu Principal\n1 - Mostrar Informacoes da rede\n2 - Inserir Endereco\n")))
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
	Test the given url + path with all the test string for a XSS attack
'''
def xss(url):
	# Read the file with input tests
	f = open("xss-strings.txt")
	inputTests = f.readlines()
	inputTests = [x.strip() for x in inputTests] 

	hdr = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
	for testString in inputTests:
		# Test the given url + path with a test string for a XSS attack
		try:
			# Do the request
			results = requests.get(url +  testString, headers= hdr)
		except (requests.exceptions.SSLError, socket.error) as e:
			results = requests.get(url +  testString, headers= hdr, verify=False)
		
		sourceCode = results.content
				
		# Search for the test string (quoted or unquoted)
		if (sourceCode.find(urllib2.unquote(testString)) >= 0) | (sourceCode.find(testString) >= 0) :
			return (True,testString)
		
		return (False,"")
	
if __name__ == '__main__':
	webIMenu('pt')