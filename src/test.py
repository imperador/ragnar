import requests, cookielib, re, sys
from urlparse import urlparse

from mimetools import Message
from StringIO import StringIO

def cleanURL(url):
    url = url.replace("\r\n", "")
    
    if ("?" in url):
        url = url.replace(" ", "")
    else:
        url = url.replace(" ", "?")

    return url

def getCSRFTokenFromHtml(respuestaHTML):
    csrf_token = ''
  
    m = re.search('var CSRF_TOKEN = \'(.+?)\'', respuestaHTML)
    if m:
        csrf_token = m.group(1)

    return csrf_token

def makePOST(url):
    print '*************************'
    url = cleanURL(url)

    parsed_path   = urlparse(url)
    URL           = DEFAULT_HOST + parsed_path[2]

    print "POST request to " + URL
    
    try:
        params = dict([p.split('=') for p in parsed_path[4].split('&')])
    except:
        params = {}

    print 'POST data:' 
    print params
    print 'headers:' 
    print headers
    print 'cookies:' 
    print cookies

    result = requests.post(URL, headers=headers, data=params, cookies=cookies)

    print '*************************'
    return result

def makeGET(url):
    print '*************************'
    parsed_path   = urlparse(url)
    URL           = DEFAULT_HOST + parsed_path[2]

    print "GET request to " + URL

    result = requests.get(URL, headers=headers, cookies=cookies)

    print 'headers:' 
    print headers
    print 'cookies:' 
    print cookies
    print '*************************'
    return result

headersFile = sys.argv[1] if len(sys.argv) >= 2 else 'headers.txt'

inputFileLines = open(headersFile, 'r').read()
requestNumber = 0


lines = inputFileLines.split('----------------------------------------------------------')

for line in lines:
    #Para cada pedido armo el post o get segun corresponda
    first_line, rest_lines_headers = line.split('\n\n', 1)
    lineas = rest_lines_headers.split('\n',1)
    
    request_line, headers_alone = rest_lines_headers.split('\n', 1)
    headers = Message(StringIO(headers_alone))

    DEFAULT_HOST = 'http://' + headers['Host']
    cookies      = {}

    for i in headers['Cookie'].split(','):
        k,v = i.split('=')
        cookies.setdefault(k,[]).append(v)
    
    
    httpMethod, relativePath, extra = request_line.split(' ',3) 

    requestNumber += 1

    if httpMethod == 'POST': 
        result = makePOST(relativePath)
        requestFileName = 'results/POST/Result-'+str(requestNumber)+'.txt'
    elif httpMethod == 'GET':
        result = makeGET(relativePath)
        requestFileName = 'results/GET/Result-'+str(requestNumber)+'.txt'    

    try:
      
      if result.status_code == 200 :
            print "Request OK status code is " + str(result.status_code)
            if (requestNumber==1):
                print "This is the first request we save cookies for future use in request headers:"   
                lItems = result.cookies.items()    
                headers = dict(lItems)
      else:
            print "Request error status code is " + str(result.status_code)

      print "\n"

      html_result = result.text.encode('utf-8')      
      
      fsalida = open(requestFileName,'w')
      fsalida.write(html_result) 
      
      fsalida.close()
    except: 
      pass



sys.exit("Error message")
















#print inputFileLines
request_line, headers_alone = inputFileLines.split('\n', 1)
headers = Message(StringIO(headers_alone))

DEFAULT_HOST = 'http://'+headers['Host']
cookies      = {}

for i in headers['Cookie'].split(','):
    k,v = i.split('=')
    cookies.setdefault(k,[]).append(v)


httpMethod, relativePath, extra = request_line.split(' ',3) 

requestNumber += 1

if httpMethod == 'POST': 
    result = makePOST(relativePath)
    requestFileName = 'results/POST/Result-'+str(requestNumber)+'.txt'
elif httpMethod == 'GET':
    result = makeGET(relativePath)
    requestFileName = 'results/GET/Result-'+str(requestNumber)+'.txt'    

try:
  
  if result.status_code == 200 :
        print "Request OK status code is " + str(result.status_code)
        if (requestNumber==1):
            print "This is the first request we save cookies for future use in request headers:"   
            lItems = result.cookies.items()    
            headers = dict(lItems)
            print headers
  else:
        print "Request error status code is " + str(result.status_code)

  print "\n"

  html_result = result.text.encode('utf-8')      
  
  fsalida = open(requestFileName,'w')
  fsalida.write(html_result) 
  
  fsalida.close()
except: 
pass