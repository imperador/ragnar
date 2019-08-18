# Ragnar
Penetration Testing Tool for Internet of Things Devices

## The Tool
Ragnar has a command line interface. It can be used as a standalone application but also allows integration into other tools through calls of its methods. It is open source to support changes on its routines and adaptations of its tests to more specific problems and further to help people who are learning how to make pentests, so it has documented descriptions of its methods. 

To support the use in different operating systems and also for code simplicity, Python 2.7 is used as the development language to perform the selected penetration tests. This choice was also made to allow any person with programming skills to adapt the code and reuse it for other pentest cases with ease. An adaptation of OpenSSL standard library on version 2.7.12 was included to allow SSLv2 and SSLv3 testing, as the language dropped support to it starting in 2.7.13 due to many vulnerabilities on these technologies.


## Modules
### Web Interface (WebI)
 > It only requires interface address to start gathering information.
 
Performs penetration testing by:
 - Establishing connections with provided interfaces
 - Tests the interface and collects necessary data
 - Analysing the field x-frame-options for Clickjacking
 - Scans for standard login pages and analyses their code
 - Tries to insert encoded SQL queries into the URLs and each detected field
   - Allows manual addition of paths 
   - Tries to generate any Database-ManagementSystem (DBMS) response \cite{su2006essence}.
 - Performs a recursive search for paths and form fields
   - Covers both persistent and reflected XSS attempts.
 - For each path and field, attempts to insert javascript strings
   - Uses several encodings to avoid dynamic detection filtering
 - Uses a technique known as ACK scan to bypass and detect any existing Web Application Firewall (WAF)

### Network Service (netServ)

Penetration testing routine: 
 - Checks for open ports and available services detection
   - Applies an SYN scan approach 
   - Can also recognise WAF presence
 - Performs randomly-generated Fuzzing attacks on all identified services 
 - Performs directed Fuzzing attacks on the well-known ports

### Cryptography (transCrypt)
Runs analysis focusing on security protocols used to establish encrypted links between the server and a client.

Testing Routine:
 - Outlines allowed security protocols
 - Verifies the default protocol used by the server
   - Classifying its cypher suite and provided bits of security. 
 - Checks the use of Perfect Forward Secrecy and used cyphers.

### Firmware (mrBin)

-

## Developer
Cristoffer Leite

GitHub: @imperador

## Referencing this work

#### \[2019\] Pentest of Internet of Things Devices
*Cristoffer Leite, João Gondim, Priscila Solis, Marcos Caetano and Eduardo Alchieri*
<br/> XLV LATIN AMERICAN COMPUTING CONFERENCE (CLEI 2019) - Forthcoming
<br/>\[pdf\] \[bib\]

#### \[2017\] Ragnar: Ferramenta para Pentest em dispositivos da Internet das Coisas
*Cristoffer Leite da Silva*
<br/> Universidade de Brasılia, 2017
<br/>[\[pdf\]](http://bdm.unb.br/bitstream/10483/19824/1/2017_CristofferLeiteDaSilva_tcc.pdf) [\[bib\]](https://scholar.googleusercontent.com/scholar.bib?q=info:lG_ooNfSqbwJ:scholar.google.com/&output=citation&scisdr=CgUlVyY-ELOVlr6fYlU:AAGBfm0AAAAAXViaelVmK9mBsGQzZdsV-iIQ_rHxUHbE&scisig=AAGBfm0AAAAAXViaensdpZkUm5jHk_Zt6pp8fkqwfAjS&scisf=4&ct=citation&cd=-1&hl=en&scfhb=1)
