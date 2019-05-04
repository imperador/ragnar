#!/usr/bin/env python

'''
	#### For this module to work, you will need to:

	1 - Install Python 2.7.12
	2 - Install pyOpenSSL
	
	.additional: If the Protocol Scan does not work on Windows, copy the file "_ssl.lib" from the project "\SSL" 
					subfolder to the folder "C:\(...)\Python27\Libs\""
	
	### This will make OpenSSL handle the SSL requisitions
'''

import base64, getpass, logging, requests, scapy, socket, time
import ssl
# import ssl as ssl # Just if it does not work on windows

# Using the ssl from python 2.12 to handle with SSL and TLS
# - Can be used: PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2
# Using the OpenSSL to the addional tests
# - Can be used will all protocols

from urlparse import urlparse

from backports.ssl_match_hostname import match_hostname, CertificateError

# Scapy functions
from scapy.all import sr
from scapy.all import sr1
from scapy.all import IP
from scapy.all import TCP
from scapy.all import RandShort

# Utils functions
from utils import bcolors
from utils import buildResponse
from utils import clear
from utils import pause
from utils import printLine

# pyOpensSSL
from OpenSSL.SSL import Context, Connection
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD, TLSv1_1_METHOD, TLSv1_2_METHOD
from OpenSSL.SSL import Error as openSSLError

# PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2
methods = {
	ssl.PROTOCOL_TLSv1_2:TLSv1_2_METHOD,
	ssl.PROTOCOL_TLSv1_1:TLSv1_1_METHOD,
	ssl.PROTOCOL_TLSv1:TLSv1_METHOD,
	ssl.PROTOCOL_SSLv23:SSLv23_METHOD,
	ssl.PROTOCOL_SSLv3:SSLv3_METHOD
}

# Protocol names used by pyOpenSSL
methodName = {
	"SSLv2":SSLv2_METHOD,
	"SSLv3":SSLv3_METHOD,
	"TLSv1":TLSv1_METHOD,
	"TLSv1.1":TLSv1_1_METHOD,
	"TLSv1.2":TLSv1_2_METHOD
}

# Relation between PFS Ciphers and their TLS/SSL protocol
pfsCipherList = {
"ECDHE-RSA-AES256-GCM-SHA384":TLSv1_2_METHOD,
"ECDHE-RSA-AES128-GCM-SHA256":TLSv1_2_METHOD,
"ECDHE-RSA-AES128-SHA256":TLSv1_2_METHOD,
"ECDHE-RSA-RC4-SHA":SSLv3_METHOD,
"DHE-RSA-AES256-GCM-SHA384":TLSv1_2_METHOD,
"DHE-RSA-AES256-SHA256":TLSv1_2_METHOD,
"DHE-RSA-AES256-SHA":SSLv3_METHOD,
"DHE-RSA-CAMELLIA256-SHA":SSLv3_METHOD,
"DHE-RSA-AES128-GCM-SHA256":TLSv1_2_METHOD,
"DHE-RSA-AES128-SHA256":TLSv1_2_METHOD,
"DHE-RSA-AES128-SHA":SSLv3_METHOD,
"DHE-RSA-CAMELLIA128-SHA":SSLv3_METHOD,
"ECDHE-RSA-AES256-SHA384":TLSv1_2_METHOD,
"ECDHE-RSA-AES256-SHA":SSLv3_METHOD,
"ECDHE-RSA-AES128-SHA":SSLv3_METHOD,
} # DHE-RSA-SEED-SHA ECDHE-RSA-RC4-SHA - Just commenting for further test implementation

'''
	Identify the standard SSL protocol being used by the server
'''
def identifyProtocol(host,port):
	# Create a list to put all analysed data
	protoDataList = []
	try:
		# Construct the socket
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		client.connect((host, port))	
		
		# Estabilish a SSL connection using the server's preferred connection
		client_ssl = Connection(Context(SSLv23_METHOD), client)
		client_ssl.set_connect_state()
		client_ssl.set_tlsext_host_name(host)
		
		# Try to perform an SSL handshake
		client_ssl.do_handshake()

		# Obtain the name of the protocol being used
		protoName = (client_ssl.get_protocol_version_name())

		# Obtain the size of the cipher being used by the protocol
		bitSize = (client_ssl.get_cipher_bits())

		# Obtain the Cipher Suite
		suite = client_ssl.get_cipher_name()

		# Create a compiled data
		data = (protoName,bitSize,suite)
		
		# Put the data obtained on the list
		protoDataList.append(data)

		# Close the connection
		client_ssl.close()
		client.close()

		# Shpw the data
		print _('Preferido: ') + str(protoName) + _('\nCifra: ') + str(suite) + _('\nTamanho em bits: ') + str(bitSize)
		
		# Return the protocol method used by pyOpenSSL
		return methodName[protoName]
	except openSSLError as e: # Server may be down or avoiding SSL connection
		print _('\nNao foi possivel identificar o protocolo padrao\n')
		return 0
	except ValueError as e: # Not configured or not allowed
		print _('\nNao foi possivel identificar o protocolo padrao\n')
		return 0


'''
	Make the table of protocols and their status 
'''
def protocolAnalysis(shouldNOTBeOffered,mustBeOffered,beingOffered):
	# Verify if the protocol should NOT be offered and print the proper result 
	if shouldNOTBeOffered:
		return buildResponse(not beingOffered,"Nao oferecido\tNAO SEGURO","Oferecido\tNAO SEGURO")
	# Verify if the protocol MUST be offered and print the proper result 
	elif mustBeOffered:
		return buildResponse(beingOffered,"Oferecido\tRECOMENDADO","Nao oferecido\tRECOMENDADO")
	# Just print if the protocol is offered or not
	elif beingOffered:
		return "Oferecido\t-"
	else:
		return "Nao oferecido\t-"

'''
	Make all the tests
'''
def transCryptDirect(lang):
	# Get the interface information
	url = raw_input(_("Endereco da interface para teste (com a porta): "))
	parsed = urlparse(url)
	if len(parsed.netloc) == 0:
		parsed = urlparse('http://'+url)
		pass

	# Getting the parsed values
	url = parsed.netloc
	if ':' in url:
		url = url.split(":",1)[0]
		port = parsed.port
	else:
		port = raw_input(_("Digite a porta: "))

	# Try to connect to the interface
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	src_port = RandShort()
	response = sr1(IP(dst=url)/TCP(sport=src_port,dport=int(port),flags="S"),timeout=3, verbose=0)

	# Verifying the existence of a service on the port
	if(str(type(response))=="<type 'NoneType'>"):
		wait = raw_input(_('Servidor Offline ou URL Invalida'))
		return
	if (not response.haslayer(TCP)):
		wait = raw_input(_('Servidor Offline ou URL Invalida'))
		return
	if (not (response.getlayer(TCP).flags == 0x12)):
		wait = raw_input(_('Servidor Offline ou URL Invalida'))
		return

	# Stealth response
	send_rst = sr(IP(dst=url)/TCP(sport=src_port,dport=int(port),flags="R"),timeout=3, verbose=0)
	clear()
	print _("[!] Servidor esta online.")	

	# Remove the / end marker
	if url.endswith('/'):
		url = url[:-1]
		pass

	# Show the Url on the top of the page
	print url +':'+ str(port)
	port = int(port)

	# [1] Testing the protocols
	printLine()
	print bcolors.HEADER + '[1] ' + bcolors.ENDC + (_('Testando Protocolos'))
	(worked,protocolList) = testProtocols(lang,url,port)
	if (not worked):
		pause()
		return

	# [2] Testing preferred protocol of the server
	printLine()
	print bcolors.HEADER + '[2] ' + bcolors.ENDC + (_('Protocolo padrao do servidor'))
	preferredProtocol = identifyProtocol(url,port)

	# [3] Testing if Perfect Forward Secrecy (PFS) is enabled on the server
	printLine()
	print bcolors.HEADER + '[3] ' + bcolors.ENDC + (_('Uso the Perfect Forward Secrecy'))
	print testPFS(url,port,preferredProtocol)

	# [4] Testing BASIC AUTH in HTTP, not so useful | Just an idea for improvement and a PoC. IF you want to use, remove the '#' in the comments below
	# printLine()
	# print bcolors.HEADER + '[4] ' + bcolors.ENDC + (_('Testando Autenticacao Basic em HTTP '))
	# print testBasicAuth(url,port)

	# [5] Test Weak Ciphers
	printLine()
	print bcolors.HEADER + '[4] ' + bcolors.ENDC + (_('Testando Cifragem Fraca  (minimo 128bits) '))
	testWeakCipher(url,port,protocolList)
	pause()


'''
	Test if sensitive data is transmitted in clear-text 
'''
def testBasicAuth(url,port):
	# Get the test credentials and generate the 
	print _('[+] Credenciais de Teste')
	userName = raw_input(_("Usuario: "))
	psswrd = getpass.getpass()
	encodedData = base64.b64encode(str(userName)+str(psswrd))
	print _('Key gerada (base64): ') + encodedData + '\n'
	
	# Make a BASIC HTTP Authentication Packet to send over the socket
	packet = 'GET / HTTP/1.1\r\nAuthorization: Basic ' + encodedData +'\r\n\r\n' # Maybe Host:www.google.com
	
	# Show the sent information
	print _('[+] Enviando Header') 
	print packet

	try:
		# Try to connect using poor configuration, with no SSL warpping at all
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(10)
		
		# Use socket to connect with the server by a specific port and send the packet
		sock.connect((url, port))
		sock.send(packet)

		# Receive the result
		return buildResponse(False,'\n',_('Resposta: ') + sock.recv(1024)[:40])
		sock.close()
	except socket.error as e:
		return buildResponse(True,_('O servidor nao esta rodando em HTTP'),'\n')
	 
	 
'''
	Test whether Perfect Forward Secrecy (PFS) is enabled on a server ( 
'''
def testPFS(host,port,protocol):
	# Create a list of pfs cipher used by the server
	pfsCipherOk = ''
	foundOne = False

	# Test each pfs cipher based on their protocol 
	for cipher in pfsCipherList.keys():
		okResult = testPFSCipher(host,port,cipher)
		if okResult:
			foundOne = True
			pfsCipherOk += (', ' if (len(pfsCipherOk)>0) else '') + cipher 
	
	return buildResponse(foundOne,_('PFS habilitado com as cifras: ') + pfsCipherOk, _('PFS nao detectado com as cifras testadas'))

'''
	Test whether Perfect Forward Secrecy (PFS) is enabled on the server
'''
def testPFSCipher(host,port,cipher):
	try:
		
		# Construct the socket
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		client.settimeout(10)
		client.connect((host, port))	
		
		# Define the method as serverpreferred and use the Cipher from the test
		contextToUse = Context(pfsCipherList[cipher])
		contextToUse.set_cipher_list(cipher) 

		# Estabilish a SSL connection using the server's preferred connection
		client_ssl = Connection(contextToUse, client)
		client_ssl.set_connect_state()
		client_ssl.set_tlsext_host_name(host)
		
		# Try to perform an SSL handshake
		client_ssl.do_handshake()

		# Close the connection
		client_ssl.close()
		client.close()
		return True 
	except openSSLError as e: # Server may be down or avoiding SSL connection
		return False
	except ValueError as e: # Not configured or not allowed
		return False
	pass

'''
	Test whether Perfect Forward Secrecy (PFS) is enabled on the server
'''
def testPFSCipherOld(url,port,cipher):
	# Initial variables
	packet, reply = "<packet>SOME_DATA</packet>", ""

	# Create
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(10)
	
	# Try to connect and return the result
	try:
		# Wrap socket with SSL properties
		wrappedSocket = ssl.wrap_socket(sock, ciphers=cipher)
		wrappedSocket.connect((url, port))
		wrappedSocket.send(packet)
		print wrappedSocket.recv(1280)

		# Close socket connection
		wrappedSocket.shutdown(socket.SHUT_RDWR)
		wrappedSocket.close()
		time.sleep(1)
		return cipher + ' OK' 
	except ssl.SSLError as sslError:
		return cipher + ' NO' 
	except socket.error as socketError:
		return cipher + ' NO' 


'''
	Test the solution to determine the use of encrypted communication between devices and btween devices and the internet
'''
def testProtocols(lang,url,port):
	# List of avaiable protocols 
	protocolList = []

	# Configure the columns
	print bcolors.BOLD + _("Protocolo\tStatus\t\tTipo") + bcolors.ENDC
	
	# Test the url for the SSLv2 protocol and analyse the result (using the pyOpenSSL)
	statusFlag = verifyOpenProtocol(url,port,SSLv2_METHOD)
	print _('- SSLv2') + "\t\t" + protocolAnalysis(True,False,statusFlag)
	if statusFlag:
		protocolList.append(ssl.PROTOCOL_SSLv2)

	# Test the url for the SSLv3 protocol and analyse the result
	statusFlag = verifyProtocol(url,port,ssl.PROTOCOL_SSLv3)
	print _('- SSLv3') + "\t\t" + protocolAnalysis(True,False,statusFlag)
	if statusFlag:
		protocolList.append(ssl.PROTOCOL_SSLv3)

	# Test the url for the TLSv1 protocol and analyse the result
	statusFlag = verifyProtocol(url,port,ssl.PROTOCOL_TLSv1)
	print _('- TLSv1') + "\t\t" + protocolAnalysis(False,False,statusFlag)
	if statusFlag:
		protocolList.append(ssl.PROTOCOL_TLSv1)

	# Test the url for the TLSv1_1 protocol and analyse the result
	statusFlag = verifyProtocol(url,port,ssl.PROTOCOL_TLSv1_1)
	print _('- TLSv1_1') + "\t" + protocolAnalysis(False,False,statusFlag)
	if statusFlag:
		protocolList.append(ssl.PROTOCOL_TLSv1_1)

	# Test the url for the TLSv1_2 protocol and analyse the result
	statusFlag = verifyProtocol(url,port,ssl.PROTOCOL_TLSv1_2)
	print _('- TLSv1_2') + "\t" + protocolAnalysis(False,True,statusFlag)
	if statusFlag:
		protocolList.append(ssl.PROTOCOL_TLSv1_2)

	# Return the result and the list obtained
	return (True,protocolList)
	# PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2

'''
	Test the solution for the use of weak ciphers
'''
def testWeakCipher(host,port,protocolList):
	# Create a list to put all analysed data
	protoDataList = []

	# Test the size of the cipher for each protocol avaiable  and get the Cipher Suite
	for proto in protocolList:
		try:
			# Construct the socket
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
			client.connect((host, port))	
			
			# Estabilish a SSL connection
			client_ssl = Connection(Context(methods[proto]), client)
			client_ssl.set_connect_state()
			client_ssl.set_tlsext_host_name(host)
			
			# Try to perform an SSL handshake
			client_ssl.do_handshake()

			# Obtain the name of the protocol being used
			protoName = (client_ssl.get_protocol_version_name())

			# Obtain the size of the cipher being used by the protocol
			bitSize = (client_ssl.get_cipher_bits())

			# Obtain the Cipher Suite
			suite = client_ssl.get_cipher_name()

			# Create a compiled data
			data = (protoName,bitSize,suite)
			
			# Put the data obtained on the list
			protoDataList.append(data)

			# Close the connection
			client_ssl.close()
			client.close()
		except openSSLError as e: # Server may be down or avoiding SSL connection
			print _('Servidor nao esta respondendo')
			return
		except ValueError as e: # Not configured or not allowed
			print _('Servidor nao esta configurado')
			return

	# Print the results
	print bcolors.BOLD + _("Protocolo\tTamanho da Cifra\tCifra") + bcolors.ENDC
	for protoData in protoDataList:
		print protoData[0] + '\t\t' + str(protoData[1]) + ' bits' + ( '(OK)' if (protoData[1] >=128) else _('(FRACA)')) + '\the\t' + str(protoData[2])

	# Connection.get_cipher_bits()

'''
	Show a basic menu 
'''
def transCryptMenu(lang):
	
	# Change the software language 
	import gettext
	global _
	if lang == 'pt':
		_ = lambda s: s
	else:
		lg = gettext.translation('transcrypt', localedir='locale', languages=[lang])
		lg.install()
		_ = lg.gettext
	
	# Basic definitions for the module menu
	menuOpts = {0:'0',1:'transCryptDirect'}

	# Network Services Menu
	subModule = {	'transCryptDirect':transCryptDirect, 		# Submodule of Web Interface tests
					}
	# Menu of the module
	while True:
		# Clean the screen
		clear()
		
		# Show the menu
		print(_('Transport Encryption Pentest'))
		opt = int(raw_input(_("0 - Voltar para o Menu Principal\n1 - Verificar SSL/TLS\n")))
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
	Verify the SSL Protocol given, using the pyOpenSSL package functions
'''
def verifyOpenProtocol(host,port,proto):
	try:
		# Construct the socket
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		client.connect((host, port))	
		
		# Estabilish a SSL connection
		client_ssl = Connection(Context(proto), client)
		client_ssl.set_connect_state()
		client_ssl.set_tlsext_host_name(host)
		
		# Try to perform an SSL handshake
		client_ssl.do_handshake()
		
		# Close the connection
		client_ssl.close()
		client.close()
	except openSSLError as e: # Server not configured to use
		return False
	except ValueError as e: # Not present
		return False
	
	# Success
	return True		


'''
	Make a connection using a SSL Protocol type and return the result (success or not)
'''
def verifyProtocol(host,port,protoVersion):
	# Set initial variables
	packet = 'GET / HTTP/1.0\r\n\r\n' if (port== 80 or port == 443) else '<packet>SOME_DATA</packet>'

	# Create a basic socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(10)

	
	# Try to connect and return the result
	try:
		# Wrap a SSL socket with the protocol using the host and port and then send a test packet
		wrappedSocket = ssl.wrap_socket(sock, ssl_version=protoVersion)
		wrappedSocket.connect((host, port))
		wrappedSocket.send(packet)
		data = wrappedSocket.recv(1280) # Just receive data - not necessary

		# Close the socket connection 
		wrappedSocket.shutdown(socket.SHUT_RDWR)	
		wrappedSocket.close()
		time.sleep(1)
		return True
	except ssl.SSLError as sslError:
		return verifyOpenProtocol(host,port,methods[protoVersion])
	# For a future improvement
	except socket.error as socketError:
		return None

if __name__ == '__main__':
	transCryptMenu('pt')
