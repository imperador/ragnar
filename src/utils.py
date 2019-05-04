'''
	Module Utils
		Functions to help on the program
'''
'''
	crackme.cenzic.com (PHP app)
	hackthissite.org
	testasp.vulnweb.com (IIS, ASP, Microsoft SQL Server), hosted by Acunetix as well
	testaspnet.vulnweb.com (IIS, ASP.NET, Microsoft SQL Server), also Acunetix
	Google Gruyere, a webapplication meant to be attacked, hosted by Google. More details on google-gruyere.appspot.com

	inurl:"index.php?cat_id="
'''
import httplib, socket, gettext, requests, urllib3

# Define login possibilities
COMMON_LOGIN_PATHS = ['admin/','login/','administrator/','admin1/','admin2/','admin3/','admin4/','_admin/','usuarios/',
'usuario/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','admin','login','administrator','admin1','admin2','admin3','admin4','_admin','usuarios',
'usuario','administrator','moderator','webadmin','adminarea','bb-admin','adminLogin','admin_area','panel-administracion','instadmin',
'memberadmin','administratorlogin','adm','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php',
'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.php','admin.php','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php',
'administrator/account.php','administrator.php','admin_area/admin.html','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php',
'bb-admin/index.html','bb-admin/login.html','acceso.php','bb-admin/admin.html','admin/home.html','login.php','modelsearch/login.php','moderator.php','moderator/login.php',
'moderator/admin.php','account.php','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.php','admincontrol.php',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html', 'adminarea/index.html','adminarea/admin.html',
'webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.php','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.php','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php','home.php','admin.php','adminarea/index.php',
'adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php',
'modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','usuarios/login.php',
'adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','user/login']

# Define common service ports and their names
COMMON_PORTS = {
    1: 'tcpmux',
    5: 'rje',
    7: 'echo',
    9: 'discard',
    11: 'systat',
    13: 'daytime',
    17: 'qotd',
    18: 'msp',
    19: 'chargen',
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    37: 'time',
    39: 'rlp',
    42: 'nameserver',
    43: 'nicname',
    49: 'tacacs',
    50: 're-mail-ck',
    53: 'domain',
    63: 'whois++',
    67: 'bootps',
    68: 'bootpc',
    69: 'tftp',
    70: 'gopher',
    71: 'netrjs-1',
    72: 'netrjs-2',
    73: 'netrjs-3',
    79: 'finger',
    80: 'http',
    88: 'kerberos',
    95: 'supdup',
    101: 'hostname',
    105: 'csnet-ns',
    106: 'poppassd',
    107: 'rtelnet',
    109: 'pop2',
    110: 'pop3',
    111: 'sunrpc',
    113: 'auth',
    115: 'sftp',
    117: 'uucp-path',
    119: 'nntp',
    123: 'ntp',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    143: 'imap',
    161: 'snmp',
    162: 'snmptrap',
    163: 'cmip-man',
    164: 'cmip-agent',
    174: 'mailq',
    177: 'xdmcp',
    178: 'nextstep',
    179: 'bgp',
    191: 'prospero',
    194: 'irc',
    199: 'smux',
    201: 'at-rtmp',
    202: 'at-nbp',
    204: 'at-echo',
    206: 'at-zis',
    209: 'qmtp',
    210: 'z39.50',
    213: 'ipx',
    220: 'imap3',
    245: 'link',
    347: 'fatserv',
    363: 'rsvp_tunnel',
    369: 'rpc2portmap',
    370: 'codaauth2',
    372: 'ulistproc',
    389: 'ldap',
    427: 'svrloc',
    434: 'mobileip-agent',
    435: 'mobilip-mn',
    443: 'https',
    444: 'snpp',
    445: 'microsoft-ds',
    464: 'kpasswd',
    468: 'puertos',
    487: 'saft',
    488: 'gss-http',
    496: 'pim-rp-disc',
    500: 'isakmp',
    515: 'printer spooler',
    519: 'utime unixtime',
    521: 'ripng',
    525: 'timed timeserver',
    532: 'netnews',
    535: 'iiop',
    538: 'gdomap',
    546: 'dhcpv6-client',
    547: 'dhcpv6-server',
    548: 'afpovertcp',
    554: 'puertos',
    556: 'remotefs',
    563: 'nntps',
    565: 'whoami',
    587: 'submission',
    610: 'npmp-local',
    611: 'npmp-gui',
    612: 'hmmp-ind',
    631: 'ipp',
    636: 'ldaps',
    674: 'acap',
    694: 'ha-cluster',
    749: 'kerberos-adm',
    750: 'kerberos-iv',
    751: 'kerberos_master',
    752: 'passwd_server',
    754: 'krb5_prop',
    760: 'krbupdate',
    765: 'webster',
    767: 'phonebook',
    808: 'omirr',
    873: 'rsync',
    953: 'rndc',
    992: 'telnets',
    993: 'imaps',
    994: 'ircs',
    995: 'pop3s',
    1080: 'socks',
    1109: 'kpop',
    1236: 'bvcontrol',
    1300: 'h323hostcallsc',
    1433: 'ms-sql-s', # SQL Slammer attacks here
    1434: 'ms-sql-m',
    1494: 'ica',
    1512: 'wins',
    1524: 'ingreslock',
    1525: 'prospero-np',
    1645: 'datametrics',
    1646: 'sa-msg-port',
    1649: 'kermit',
    1701: 'l2tp',
    1718: 'h323gatedisc',
    1719: 'h323gatestat',
    1720: 'h323hostcall',
    1758: 'tftp-mcast',
    1789: 'hello',
    1812: 'radius',
    1813: 'radius-acct',
    1911: 'mtp',
    1985: 'hsrp',
    1986: 'licensedaemon',
    1997: 'gdp-port',
    2049: 'nfs',
    2053: 'knetd',
    2102: 'zephyr-srv',
    2103: 'zephyr-clt',
    2104: 'zephyr-hm',
    2105: 'eklogin',
    2150: 'ninstall',
    2401: 'cvspserver',
    2600: 'hpstgmgr [zebrasrv]',
    2601: 'discp-client [zebra]',
    2602: 'discp-server [ripd]',
    2603: 'servicemeter [ripngd]',
    2604: 'nsc-ccs [ospfd]',
    2605: 'nsc-posa',
    2606: 'netmon [ospf6d]',
    2809: 'corbaloc',
    2988: 'afbackup',
    3130: 'icpv2',
    3306: 'mysql',
    3346: 'trnsprntproxy',
    3455: 'prsvp',
    4011: 'pxe',
    4321: 'rwhois',
    4444: 'krb524',
    5002: 'rfe',
    5232: 'sgi-dgl',
    5308: 'cfengine',
    5354: 'noclog',
    5355: 'hostmon',
    5432: 'postgres',
    5999: 'cvsup',
    6667: 'ircd',
    7000: 'afs3-fileserver',
    7001: 'afs3-callback',
    7002: 'afs3-prserver',
    7003: 'afs3-vlserver',
    7004: 'afs3-kaserver',
    7005: 'afs3-volser',
    7006: 'afs3-errors',
    7007: 'afs3-bos',
    7008: 'afs3-update',
    7009: 'afs3-rmtsys',
    8008: 'http-alt',
    8080: 'webcache',
    8081: 'tproxy',
    9359: 'mandelspawn mandelbrot',
    9876: 'sd',
    10080: 'amanda',
    10081: 'kamanda',
    11371: 'pgpkeyserver',
    11720: 'h323callsigalt',
    13720: 'bprd',
    13721: 'bpdbm',
    13722: 'bpjava-msvc',
    13724: 'vnetd',
    13782: 'bpcd',
    13783: 'vopied',
    20011: 'isdnlog',
    20012: 'vboxd',
    22273: 'wnn6 wnn4',
    24554: 'binkp',
    26000: 'quake',
    26208: 'wnn6-ds',
    27374: 'asp',
    # 31337: 'tcpwrapped', # 1337 joke on tcpwrapped protection
    33434: 'traceroute',
    60177: 'tfido',
    60179: 'fido'
}


'''
    Define common colours
'''
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

'''
    Stantard response maker
''' 
def buildResponse(test, result1, result2):
    return (bcolors.OKGREEN + result1 + bcolors.ENDC) if (test) else (bcolors.WARNING + result2 + bcolors.ENDC)
    pass

'''
    Clear the screen
'''
def clear():
	import os
	os.system('cls' if os.name=='nt' else 'clear')  # For Windows and Linux/OSX
	printLine()

# Just an idea
def request(metodo,url,flags,excep):
	requests.get(metodo+url,flags)
	pass

'''
    Print a separation line
'''
def printLine():
	print "=" * 60
	pass

'''
    Try to get the login page
'''
def getLoginPage(site, lang):
	pageFound=0
	var2=0
	hdr = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	global _
	_ = lambda s: s
	
	print("[+] Escaneando " + site + "...")
	msg = _('Nenhum caminho encontrado')
	pageList = []
	for admin in COMMON_LOGIN_PATHS:
		admin = admin.replace("\n","")
		admin = "/" + admin
		host = site + admin

		try:
			response = requests.get('http://'+host, headers = hdr)
		except requests.exceptions.SSLError as e:
			response = requests.get('http://'+host, headers = hdr, verify=False)
			pass
		except requests.ConnectionError as a: # No connection (there is nothing on this path)
			continue
		sourceCode = response.content
		var2 = var2 + 1
		# If there is a page (Code 200) and there is no error on the response, add to the list
		if (response.status_code == 200) & ((sourceCode.find('<input') != -1)):
			# Verify repetions
			if not ((admin in pageList) | ((admin+'/') in pageList)):
				pageList.append(admin)
				pageFound = pageFound + 1
				msg = _('Caminhos comuns encontrados!')
				pass
		elif response.status_code == 404:
			var2 = var2
			pass
		# Verify redirection (Code 302)
		elif response.status_code == 302:
			path = (response.url).replace('http://'+site,"")
			path = path.split("?",1)[0]
			# Verify repetions
			if not (path in pageList):
				pageList.append(path)
				pageFound = pageFound + 1
				msg = _('Caminhos comuns encontrados!')
				pass
			pass
		response.close()
		'''	else: # Can treat other cases, but it is not be necessary until now
			print "%s %s %s" % ("\t[!] " + host, " Interesting response:", response.status)'''
	return {'msg':msg,'pageFound':pageFound,'pageList':pageList}


'''
    Pause function
'''
def pause():
	wait = raw_input(_('---Pressione \"ENTER\" para continuar---'))

'''
    Return the name of a file with underline
'''
def underName(name):
    return bcolors.UNDERLINE + name + bcolors.ENDC

'''
    Define common user agent to estabilish a connection
'''
def userAgent():
    uAgent=[]
    uAgent.append("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14")
    uAgent.append("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0")
    uAgent.append("Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3")
    uAgent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
    uAgent.append("Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7")
    uAgent.append("Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)")
    uAgent.append("Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1")
    return uAgent

global _
_ = lambda s: s