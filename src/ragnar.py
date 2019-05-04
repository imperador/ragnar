'''
	Project Ragnar
		Program for Penetration test on IoT devices. 
'''
#!/usr/bin/python
import os, sys, inspect, gettext
import webI, netServ
from utils import clear
from utils import printLine
from utils import bcolors
from utils import getLoginPage

# Multilanguage support (pt and en)
# Use: {'en':'', 'pt':''}
langSelec = {'en':'English selected', 'pt': 'Portugues selecionado'}
# python C:\Python27\Tools\i18n\pygettext.py -d ragnar ragnar.py

# Basic definitions for the program
menuOpts = {0:'exit',1:'webI',2:'netServ'}
langOpts = {'en','pt'}

'''
	Main Class of the program, coordinate all penetration tests
	using the other modules. It's the core of the software.
'''

'''
	If the module is called with 'python ragnar.py', this tests are executed.
'''
# Language Selection
while True:
	lang = raw_input("'pt' - Portugues\n'en' - English\n")
	if lang in langOpts:
		print(langSelec[lang])
		break

# Change the software language 
if lang == 'pt':
	_ = lambda s: s
else:
	lg = gettext.translation('ragnar', localedir='locale', languages=[lang])
	lg.install()

# Main Menu and submodules definition
print(_('Escolha o Modulo a ser executado'))
subModule = {	'exit':sys.exit, 	# Close the program
				'webI':webI.webIMenu, 		# Submodule of Web Interface tests
				'netServ':netServ.netServMenu, 		# Submodule of Web Interface tests
				}
# Selection of the module
while True:
	# Clean the screen
	clear()
	opt = int(raw_input(_("0 - Fechar o Programa\n1 - Interface Web \n2 - Servicos de Rede\n")))
	if opt == 0:
		sys.exit()
	if opt in menuOpts:
		subModule[menuOpts[opt]](lang)
	else:
		print _('Escolha invalida')
		

		
