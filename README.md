# monitorizador
Script para monitorização de IPs e domínios

Primeiro correr:

```bash
pip3 install -r requirements.txt
```
Correr o comando:

sudo python3 allFiles.py ips.txt dominios.txt 

ATENÇÃO!!!
-A interface do comando masscan deve ser alterada 
-Limpar a base de dados apenas na primera execução, depois comentar linha da main que
tem a função deleteTabels() 
...
Exemplo de output esperado:

[+] Running the masscan enumeration:  masscan 172.67.74.154 --rate=1500 -p0-65535 -e enp0s3 -oJ mscan.json

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2022-10-04 10:07:14 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
2022-10-04 11:08:10,401 [INFO] root: Nmap parsing '172.67.74.154.xml'        
2022-10-04 11:08:10,401 [DEBUG] NmapXMLInmporter: Processing 172.67.74.154.xml
2022-10-04 11:08:10,401 [DEBUG] NmapXMLInmporter: 172.67.74.154 -> []
2022-10-04 11:08:10,401 [INFO] NmapXMLInmporter: Opening database: monitorizadorIPs.db
2022-10-04 11:08:10,421 [DEBUG] NmapXMLInmporter: INSERT INTO `Host`(`Address`,`Name`) VALUES (?,?)
2022-10-04 11:08:10,421 [DEBUG] NmapXMLInmporter: ('172.67.74.154', None)
2022-10-04 11:08:10,421 [DEBUG] NmapXMLInmporter: INSERT INTO `Time`(HostID, `Time`) VALUES (?,?)
2022-10-04 11:08:10,421 [DEBUG] NmapXMLInmporter: (1, datetime.datetime(2022, 10, 4, 11, 8, 10, 421754))
allFiles.py:464: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  answers = my_resolver.query(query, "A")
WARNING: Timeout querying b.barracudacentral.org
WARNING: Timeout querying bl.spamcannibal.org
WARNING: Timeout querying bl.spamcop.net
WARNING: Timeout querying blacklist.woody.ch
WARNING: Timeout querying cbl.abuseat.org
WARNING: No answer for cdl.anti-spam.org.cn
WARNING: Timeout querying combined.abuse.ch
WARNING: Timeout querying combined.rbl.msrbl.net
WARNING: Timeout querying db.wpbl.info
WARNING: Timeout querying dnsbl-1.uceprotect.net
WARNING: Timeout querying dnsbl-2.uceprotect.net
WARNING: Timeout querying dnsbl-3.uceprotect.net
WARNING: Timeout querying dnsbl.cyberlogic.net
WARNING: Timeout querying dnsbl.sorbs.net
allFiles.py:465: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  answer_txt = my_resolver.query(query, "TXT")
172.67.74.154 is listed in dnsbl.spfbl.net (127.0.0.4: "https://matrix.spfbl.net/172.67.74.154")
WARNING: Timeout querying drone.abuse.ch
WARNING: Timeout querying drone.abuse.ch
WARNING: Timeout querying duinv.aupads.org
WARNING: Timeout querying dul.dnsbl.sorbs.net
WARNING: Timeout querying dul.ru
WARNING: Timeout querying dyna.spamrats.com
WARNING: Timeout querying dynip.rothen.com
WARNING: Timeout querying http.dnsbl.sorbs.net
WARNING: Timeout querying images.rbl.msrbl.net
WARNING: Timeout querying ips.backscatterer.org
WARNING: Timeout querying ix.dnsbl.manitu.net
WARNING: Timeout querying korea.services.net
WARNING: Timeout querying misc.dnsbl.sorbs.net
WARNING: Timeout querying noptr.spamrats.com
WARNING: Timeout querying ohps.dnsbl.net.au
WARNING: Timeout querying omrs.dnsbl.net.au
WARNING: Timeout querying orvedb.aupads.org
WARNING: Timeout querying osps.dnsbl.net.au
WARNING: Timeout querying osrs.dnsbl.net.au
WARNING: Timeout querying owfs.dnsbl.net.au
WARNING: Timeout querying pbl.spamhaus.org
WARNING: Timeout querying phishing.rbl.msrbl.net
WARNING: Timeout querying probes.dnsbl.net.au
WARNING: Timeout querying proxy.bl.gweep.ca
WARNING: Timeout querying rbl.interserver.net
WARNING: Timeout querying rdts.dnsbl.net.au
WARNING: Timeout querying relays.bl.gweep.ca
WARNING: Timeout querying relays.nether.net
WARNING: Timeout querying residential.block.transip.nl
WARNING: Timeout querying ricn.dnsbl.net.au
WARNING: Timeout querying rmst.dnsbl.net.au
WARNING: Timeout querying smtp.dnsbl.sorbs.net
WARNING: Timeout querying socks.dnsbl.sorbs.net
WARNING: Timeout querying spam.abuse.ch
WARNING: Timeout querying spam.dnsbl.sorbs.net
WARNING: Timeout querying spam.rbl.msrbl.net
WARNING: Timeout querying spam.spamrats.com
WARNING: Timeout querying spamrbl.imp.ch
WARNING: Timeout querying t3direct.dnsbl.net.au
WARNING: Timeout querying tor.dnsbl.sectoor.de
WARNING: Timeout querying torserver.tor.dnsbl.sectoor.de
WARNING: Timeout querying smtp.dnsbl.sorbs.net
WARNING: Timeout querying socks.dnsbl.sorbs.net
WARNING: Timeout querying spam.abuse.ch
WARNING: Timeout querying spam.dnsbl.sorbs.net
WARNING: Timeout querying spam.rbl.msrbl.net
WARNING: Timeout querying spam.spamrats.com
WARNING: Timeout querying spamrbl.imp.ch
WARNING: Timeout querying t3direct.dnsbl.net.au
WARNING: Timeout querying tor.dnsbl.sectoor.de
WARNING: Timeout querying torserver.tor.dnsbl.sectoor.de
WARNING: Timeout querying ubl.lashback.com
WARNING: Timeout querying ubl.unsubscore.com
WARNING: Timeout querying virus.rbl.jp
WARNING: Timeout querying virus.rbl.msrbl.net
WARNING: Timeout querying web.dnsbl.sorbs.net
WARNING: Timeout querying wormrbl.imp.ch
WARNING: Timeout querying xbl.spamhaus.org
WARNING: Timeout querying zen.spamhaus.org
WARNING: Timeout querying zombie.dnsbl.sorbs.net
2022-10-04 11:28:59,951 [DEBUG] urllib3.connectionpool: Starting new HTTPS connection (1): crt.sh:443
2022-10-04 11:29:12,027 [DEBUG] urllib3.connectionpool: https://crt.sh:443 "GET /?q=%25.cybers3c.pt&output=json HTTP/1.1" 503 1761
[X] Information not available! Running...
2022-10-04 11:29:12,032 [DEBUG] urllib3.connectionpool: Starting new HTTPS connection (1): crt.sh:443
2022-10-04 11:29:17,310 [DEBUG] urllib3.connectionpool: https://crt.sh:443 "GET /?q=%25.cybers3c.pt&output=json HTTP/1.1" 200 None

[!] ---- TARGET: cybers3c.pt ---- [!] 

2022-10-04 11:29:17,812 [DEBUG] urllib3.connectionpool: Starting new HTTPS connection (1): crt.sh:443
2022-10-04 11:29:26,577 [DEBUG] urllib3.connectionpool: https://crt.sh:443 "GET /?q=%25.cybers3c.pt&output=json HTTP/1.1" 200 None

[!] ---- TARGET: cybers3c.pt ---- [!] 

TLSv1_3: True
TLSv1_2: True
TLSv1_1: True
TLSv1: True
SSLv2: False
SSLv3: False
Header 'x-frame-options' contains value 'SAMEORIGIN' ... [ OK ]
Header 'strict-transport-security' contains value 'max-age=31536000' ... [ OK ]
Header 'access-control-allow-origin' is missing ... [ OK ]
Header 'content-security-policy' contains value 'script-src 'unsafe-eval' 'unsafe-inline' 'self' https://cdnjs.cloudflare.com https://ajax.googleapis.com https://maps.googleapis.com https://fonts.googleapis.com/ https://www.facebook.com/ https://www.facebook.net/ https://connect.facebook.net https://connect.facebook.com https://www.cybers3c.pt' ... [ OK ]
Header 'x-xss-protection' contains value '1; mode=block' ... [ OK ]
Header 'x-content-type-options' contains value 'nosniff' ... [ OK ]
Header 'x-powered-by' contains value 'PHP/7.4.30' ... [ WARN ]
Header 'server' contains value 'cloudflare' ... [ WARN ]
HTTPS supported ... [ OK ]
HTTPS valid certificate ... [ OK ]
HTTP -> HTTPS redirect ... [ OK ]
allFiles.py:733: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  answers = my_resolver.query(query, "A")
WARNING: Timeout querying b.barracudacentral.org
WARNING: Timeout querying bl.spamcannibal.org
WARNING: Timeout querying bl.spamcop.net
WARNING: Timeout querying blacklist.woody.ch
WARNING: Timeout querying cbl.abuseat.org
WARNING: No answer for cdl.anti-spam.org.cn
WARNING: Timeout querying combined.abuse.ch
WARNING: Timeout querying combined.rbl.msrbl.net
WARNING: Timeout querying db.wpbl.info
WARNING: Timeout querying dnsbl-1.uceprotect.net
WARNING: Timeout querying dnsbl-2.uceprotect.net
WARNING: Timeout querying dnsbl-3.uceprotect.net
WARNING: Timeout querying dnsbl.cyberlogic.net
WARNING: Timeout querying dnsbl.sorbs.net
allFiles.py:734: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  answer_txt = my_resolver.query(query, "TXT")
104.26.12.174 is listed in dnsbl.spfbl.net (127.0.0.4: "https://matrix.spfbl.net/104.26.12.174")
WARNING: Timeout querying drone.abuse.ch
WARNING: Timeout querying drone.abuse.ch
WARNING: Timeout querying duinv.aupads.org
WARNING: Timeout querying dul.dnsbl.sorbs.net
WARNING: Timeout querying dul.ru
WARNING: Timeout querying dyna.spamrats.com
WARNING: Timeout querying dynip.rothen.com
WARNING: Timeout querying http.dnsbl.sorbs.net
WARNING: Timeout querying images.rbl.msrbl.net
WARNING: Timeout querying ips.backscatterer.org
WARNING: Timeout querying ix.dnsbl.manitu.net
WARNING: Timeout querying korea.services.net
WARNING: Timeout querying misc.dnsbl.sorbs.net
WARNING: Timeout querying noptr.spamrats.com
WARNING: Timeout querying ohps.dnsbl.net.au
WARNING: Timeout querying omrs.dnsbl.net.au
WARNING: Timeout querying orvedb.aupads.org
WARNING: Timeout querying osps.dnsbl.net.au
WARNING: Timeout querying osrs.dnsbl.net.au
WARNING: Timeout querying owfs.dnsbl.net.au
WARNING: Timeout querying pbl.spamhaus.org
WARNING: Timeout querying phishing.rbl.msrbl.net
WARNING: Timeout querying probes.dnsbl.net.au
WARNING: Timeout querying proxy.bl.gweep.ca
WARNING: Timeout querying rbl.interserver.net
WARNING: Timeout querying rdts.dnsbl.net.au
WARNING: Timeout querying relays.bl.gweep.ca
WARNING: Timeout querying relays.nether.net
WARNING: Timeout querying residential.block.transip.nl
WARNING: Timeout querying ricn.dnsbl.net.au
WARNING: Timeout querying rmst.dnsbl.net.au
WARNING: Timeout querying smtp.dnsbl.sorbs.net
WARNING: Timeout querying socks.dnsbl.sorbs.net
WARNING: Timeout querying spam.abuse.ch
WARNING: Timeout querying spam.dnsbl.sorbs.net
WARNING: Timeout querying spam.rbl.msrbl.net
WARNING: Timeout querying spam.spamrats.com
WARNING: Timeout querying spamrbl.imp.ch
WARNING: Timeout querying t3direct.dnsbl.net.au
WARNING: Timeout querying tor.dnsbl.sectoor.de
WARNING: Timeout querying torserver.tor.dnsbl.sectoor.de
WARNING: Timeout querying ubl.lashback.com
WARNING: Timeout querying ubl.unsubscore.com
WARNING: Timeout querying virus.rbl.jp
WARNING: Timeout querying virus.rbl.msrbl.net
WARNING: Timeout querying web.dnsbl.sorbs.net
WARNING: Timeout querying wormrbl.imp.ch
WARNING: Timeout querying xbl.spamhaus.org
WARNING: Timeout querying zen.spamhaus.org
WARNING: Timeout querying zombie.dnsbl.sorbs.net



