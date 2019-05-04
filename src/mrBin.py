'''
	
	#### For this module to work, you will need to:

	1 - Install python-magic
		https://github.com/ahupp/python-magic

	#### 

https://www.owasp.org/index.php/IoT_Firmware_Analysis#Obtain_and_Analyze_Firmware

1	Obtain and Analyze Firmware
1.1	Obtain Firmware
1.2	Analyze Firmware File
1.3	Extracting the File System from the Firmware File
1.4	Using the Firmware Modification Kit
1.5	Extracting and Running Binaries
1.6	Extracting a jffs2 file system
1.7	Extracting from a CPIO archive file
1.8	Extracting from a UBI file system
1.9	Mounting a .ext2 file
1.10	Things to check for once the file system is mounted or extracted
1.11	Dynamic testing of a web admin interface without the device
'''

import hashlib, magic, shutil, string, uefi_firmware

# Utils functions
from utils import bcolors
from utils import buildResponse
from utils import clear
from utils import pause
from utils import printLine
from utils import underName

'''

'''
def binExtract(fileName):
	# Generate the file descriptor using the file name
	with open(fileName, 'r') as outFile:
		file_content = outFile.read()
	
	# Parse the File content
	parser = uefi_firmware.AutoParser(file_content)
	firmwareData = parser.parse()
	
	# If the file has a known type, extract the content 
	if parser.type()=='unknown':
		firmwareContent = '' 
	else:
		firmwareContent = firmwareData.showinfo()
	return _('Resultado: ') + parser.type() + '\n' + buildResponse(parser.type()=='unknown',_('Sistema de arquivos nao identificado'),_('Sistema de arquivo identificado:\n') + firmwareContent) 
	
'''
'''
def catFile():
	with open('command.fort.13', 'wb') as outFile:
	    with open('command.info', 'rb') as com, open('fort.13', 'rb') as fort13:
	        shutil.copyfileobj(com, outFile)
	        shutil.copyfileobj(fort13, outFile)
	pass

'''
	Check the MD5 of a file (simulates md5sum command)
'''
def md5sum(fileName):
	hash_md5 = hashlib.md5()
	with open(fileName, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

'''
	Get the type of a file (simulates File command)
'''
def getType(fileName):

	typeF = magic.Magic(mime=True, uncompress=True, magic_file="Magics\magic.mgc")
	return str(typeF.from_file(fileName))
	
'''
	Show a basic menu 
'''
def mrBinMenu(lang):
	# Import the clear function
	global clear
	
	# Change the software language 
	import gettext
	global _
	if lang == 'pt':
		_ = lambda s: s
	else:
		lg = gettext.translation('mrBin', localedir='locale', languages=[lang])
		lg.install()
		_ = lg.gettext
	
	# Basic definitions for the module menu
	menuOpts = {0:'0',1:'mrBinDirect'}

	# Network Services Menu
	subModule = {	'mrBinDirect':mrBinDirect, 		# Submodule of Web Interface tests
					}
	# Menu of the module
	while True:
		# Clean the screen
		clear()
		
		# Show the menu
		print(_('Firmware Pentest'))
		opt = int(raw_input(_("0 - Voltar para o Menu Principal\n1 - Verificar Arquivo de Firmware\n")))
		if opt == 0:
			return
		if opt in menuOpts:
			subModule[menuOpts[opt]](lang)
		else:
			clear()
			print _('Escolha invalida')

'''
	
'''
def mrBinDirect(lang):
	# Get the file information
	fileName = raw_input(_("Arquivo: "))
	clear()

	# Print the file type
	print bcolors.BOLD + _('Arquivo \'{}\'').format(underName(fileName)) + bcolors.ENDC
	print _('Tipo: ') + getType(fileName)

	# Print the md5 value
	md5Value = md5sum(fileName)
	print _('MD5 signature: ') + md5Value

	## TEST SECTION

	# [1] Verify the MD5 signature with a MD5 file
	printLine()
	print '[1] '+ (_('Verificacao do MD5'))
	print _('Procurando arquivo \'{}\'').format(underName(fileName+'.md5'))
	print compareMd5File(fileName+'.md5',md5Value)

	# [2] Finding printable strings on the bin file
	printLine()
	print '[2] '+ (_('Analise de Palavras Legiveis')) 
	print findStrings(fileName,10)

	# [3] Dumphex data from the Bin file
	printLine()
	print '[3] '+ (_('Executando Hex Dump no firmware'))
	print dumpFileContent(fileName)

	# [4] Tentativa de extracao do sistema de arquivos
	printLine()
	print '[4] '+ (_('Tentativa de Extracao do Sistema de Arquivos'))
	print binExtract(fileName)
	pause()

'''
	Get the file content, convert to a readable hexadecimal format and dump the result on a new file
'''
def dumpFileContent(fileName):
	# Get the file content
	fileContent = readFile(fileName)

	# Convert the content of the file to a readable hex format
	hexContent = hexdump(fileContent)

	# Dump the result on a new file
	resultFile = 'hex-{}.txt'.format(fileName)
	saveList(resultFile,hexContent)

	# Return the result
	return _('Dump salvo no arquivo \'{}\'').format(underName(resultFile))

'''
	Dump the content of the file in hexadecimal
'''
def readFile(fileName):
	# Start the file content as empty
	fileContent = ''

	# Read the file
	with open(fileName, 'rb') as f:
		for chunk in iter(lambda: f.read(32), b''):
			fileContent += chunk
	return fileContent

'''
	Dump the source content
'''
def hexdump(src, length=16, sep='.'):
	# Get the pattern and the filter 
	displayValue = string.digits + string.letters + string.punctuation
	filterContent = ''.join(((x if x in displayValue else '.') for x in map(chr, range(256))))
	
	# Start the result as empty
	lines = []
	
	# Read the content, convert to hex and save on a list
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		if len(hex) > 24:
			hex = "%s %s" % (hex[:24], hex[24:])
		printable = ''.join(["%s" % filterContent[ord(x)] for x in chars])
		lines.append("%08x:  %-*s  |%s|" % (c, length*3, hex, printable))
	
	# Return the result
	return lines

'''
	Search for printable strings on a file and print the result list on a TXT file for future analysis
'''
def findStrings(fileName,size):
	print _('Analisando strings de tamanho minimo {}').format(size)

	# Get the list with the printable strings
	listResult = list(strings(fileName,size))

	# Save the list on a file
	resultFile = 'strings-{}.txt'.format(fileName)
	saveList(resultFile,listResult)

	# Return the result
	return _('String salvas no arquivo \'{}\'').format(underName(resultFile))

'''
	Write the list on a file
'''
def saveList(fileName,listSource):
	# Open the file
	thefile = open(fileName, 'w')
	
	# Save each item on a line
	for item in listSource:
		thefile.write("%s\n" % item)

	return True

'''
	Compare a Md5 from a file with the given one
'''
def compareMd5File(fileName,md5Value):

	# Try to read the file 
	try:
		with open(fileName, 'r') as fp:
			md5Check = fp.read()
	except IOError as e:
		# If fails to find the file, print a message
		return _('Arquivo nao encontrado!')

	# Return a msg depending if the search was successful or not
	return _('Arquivo encontrado!\n MD5: {}').format(md5Check) + buildResponse(fileFound == md5Value,_(' Valido '),_(' nao confere\n'))

		

	
	return buildResponse(fileFound,)

'''
	Get all printable characters of a file given a minimum size (simulates strings command)
'''
def strings(fileName, min):
	with open(fileName, "rb") as f: 
		result = ""
		for c in f.read():
			if c in string.printable:
				result += c
				continue
			if len(result) >= min:
				yield result
			result = ""
		if len(result) >= min:  # catch result at EOF
			yield result


if __name__ == '__main__':
	mrBinMenu('pt')

