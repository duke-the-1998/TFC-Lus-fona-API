#!/usr/bin/env python3

import argparse
import http.client
import re
import socket
import sqlite3
import ssl
import sys
import urllib.request
from urllib.parse import urlparse

import requests

#import securityheaders


#-------auxiliares-------------
def is_valid_domain(str):
 
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
     
    p = re.compile(regex)
 	 
    if str != None and re.search(p, str):
        return True

def deleteTabels():
    db = "monitorizadorIPs.db"
    conn = sqlite3.connect(db)
    conn.execute(''' DROP TABLE IF EXISTS `Subdomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Security Headers`;''')
    
    conn.execute(''' DROP TABLE IF EXISTS `SSL/TLS`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Domains`;''')
    
    conn.commit()

#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + "\n")
		f.close()

def subdomains(domains):

	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)

	s = []
	subdomains = []
	target = clear_url(domains)
	output = domains+".txt"

	req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))

	if req.status_code != 200:
		print("[X] Information not available!") 
		return None

	conn.execute('''
            CREATE TABLE IF NOT EXISTS `Subdomains` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                Domain_ID INTEGER,
                Subdomain TEXT,
                StartDate TEXT,
                EndDate TEXT,
                Country TEXT,
                CA TEXT,
                FOREIGN KEY (Domain_ID) REFERENCES `Domains`(ID)
            );
            ''')

	subdomain_info = list()
	for value in req.json():
		subdomains = str(value['name_value']).split("\n")
		
		for subdomain in subdomains: 
		
			if subdomain not in subdomain_info and not re.search("^[*.]", subdomain):
				subdomain_info.append(subdomain)
				
				startDate = value['not_before'].split("T")[0]
				endDate = value['not_after'].split("T")[0]
				country = value['issuer_name'].split(",")[0].split("=")[1]
				ca = value['issuer_name'].split(",")[1].split("=")[1]

				sql = 'SELECT ID FROM Domains WHERE Domains=?'
				values = (domains,)
				domID = conn.execute(sql, values).fetchall()
				domID = domID[0][0]

				sql = 'INSERT INTO `Subdomains`(ID, Domain_ID, Subdomain, StartDate, EndDate, Country, CA) VALUES (?,?,?,?,?,?,?)'
				values = (None, domID, subdomain, startDate, endDate, country, ca )
				conn.execute(sql, values)
				conn.commit()

	print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

'''
for subdomain in res_list:
		print("{s}".format(s=subdomain))

		if output is not None:
			save_subdomains(subdomain,output)
'''

#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `SSL/TLS` (
				ID INTEGER PRIMARY KEY,
				SSLv2 TEXT,
				SSLv3 TEXT,
				TLSv1 TEXT,
				TLSv1_1 TEXT,
				TLSv1_2 TEXT,
				TLSv1_3 TEXT,
				FOREIGN KEY (ID) REFERENCES `Domains`(ID)
		);
		''')

	context = ssl.create_default_context()
	
	with socket.create_connection((hostname, 443)) as sock:
		with context.wrap_socket(sock, server_hostname=hostname) as ssock:
			if ssock.version():
				#PERGUNTAR PELA VERSAO TLS FAVORITA
				print(ssock.version())
				print("TLSv1_3: "+str(ssl.HAS_TLSv1_3))
				print("TLSv1_2: "+str(ssl.HAS_TLSv1_2))
				print("TLSv1_1: "+str(ssl.HAS_TLSv1_1))
				print("TLSv1: "+str(ssl.HAS_TLSv1))
				print("SSLv2: "+str(ssl.HAS_SSLv2))
				print("SSLv3: "+str(ssl.HAS_SSLv3))

				TLSv1_3 = str(ssl.HAS_TLSv1_3)
				TLSv1_2 = str(ssl.HAS_TLSv1_2)
				TLSv1_1 = str(ssl.HAS_TLSv1_1)
				TLSv1 = str(ssl.HAS_TLSv1)
				SSLv2 = str(ssl.HAS_SSLv2)
				SSLv3 = str(ssl.HAS_SSLv3)

				sql = 'INSERT INTO `SSL/TLS`(ID, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 ) VALUES (?,?,?,?,?,?,?)'
				values = (None, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3)
				
				conn.execute(sql, values)
				conn.commit()
				#print(ssock.getpeercert(binary_form=False))
			else:
				print("Not found")


#verificar com outros outputs 
def create_domains_table(domain):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `Domains` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				Domains TEXT
		);
		''')

	sql = 'INSERT INTO `Domains`(ID, Domains) VALUES (?,?)'
	values = (None, domain)
	
	conn.execute(sql, values)
	conn.commit()


class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):
        """ Risk evaluation function.
        Set header warning flag (1/0) according to its contents.
        Args:
            header (str): HTTP header name in lower-case
            contents (str): Header contents (value)
        """
        warn = 1

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1

        if header == 'strict-transport-security':
            warn = 0

        """ Evaluating the warn of CSP contents may be a bit more tricky.
            For now, just disable the warn if the header is defined
            """
        if header == 'content-security-policy':
            warn = 0

        """ Raise the warn flag, if cross domain requests are allowed from any 
            origin """
        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0

        if header.lower() == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        """ Enable warning if backend version information is disclosed """
        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        sslerror = False
            
        conn = http.client.HTTPSConnection(hostname, context = ssl.create_default_context() )
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:
            sslerror = True

        # if tls connection fails for unexcepted error, retry without verifying cert
        if sslerror:
            conn = http.client.HTTPSConnection(hostname, timeout=5, context = ssl._create_stdlib_context() )
            try:
                conn.request('GET', '/')
                res = conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http' # default to http if protocl scheme not specified

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if (protocol == 'http'):
            conn = http.client.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print('HTTP request failed')
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1) 

        return False

    def check_headers(self, domain, url, follow_redirects = 0):

        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''} 
        }

        
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = http.client.HTTPConnection(hostname)
        elif (protocol == 'https'):
                # on error, retry without verifying cert
                # in this context, we're not really interested in cert validity
                ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(hostname, context = ctx )
        else:
            """ Unknown protocol scheme """
            return {}

        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
            
        except socket.gaierror:
            print('HTTP request failed')
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0].lower() == 'location'):
                    redirect_url = header[1]
                    if not re.match('^https?://', redirect_url):
                        redirect_url = protocol + '://' + hostname + redirect_url
                    return self.check_headers(redirect_url, follow_redirects - 1) 

        db = "monitorizadorIPs.db"
        conn = sqlite3.connect(db)

        conn.execute('''
            CREATE TABLE IF NOT EXISTS `Security Headers` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                Subdomain_ID INTEGER,
                Header TEXT,
                Info TEXT,
                Status TEXT,
                FOREIGN KEY (Subdomain_ID) REFERENCES `Subdomains`(ID)
            );
            ''')

        for header in headers:

            a = header
            #set to lowercase before the check
            headerAct = header[0].lower()

            if (headerAct in retval):
                retval[headerAct] = self.evaluate_warn(headerAct, header[1])
        
        sql='SELECT ID FROM `Subdomains` WHERE `Subdomain`=?'
        #Problemas aqui, nao consigo ir buscar o valor do ID do Subdomain
        values = (domain,)
        domId = conn.execute(sql, values).fetchall()
        domId = dom[0][0]
        
        sql = 'INSERT INTO `Security Headers`(ID, Subdomain_ID, Header, Info, Status) VALUES (?,?,?,?,?)'
        values = (None, domId, a, headerAct, 'ok' )
        conn.execute(sql, values)
        conn.commit()

        return retval

        

    #if __name__ == "__main__":
def secHead(domain):

#  parser = argparse.ArgumentParser(description='Check HTTP security headers', \
#     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
#  parser.add_argument('url', metavar='URL', type=str, help='Target URL')
#  parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
#  args = parser.parse_args()
#  url = args.url
    url = domain

# redirects = args.max_redirects
    redirects = 6

    foo = SecurityHeaders()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided


    headers = foo.check_headers(domain, url, redirects)

    if not headers:
        print ("Failed to fetch headers, exiting...")
        sys.exit(1)

    okColor = '\033[92m'
    warnColor = '\033[93m'
    endColor = '\033[0m'
    for header, value in headers.items():
        if value['warn'] == 1:
            if value['defined'] == False:
                print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')
            else:
                print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                    ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
        elif value['warn'] == 0:
            if value['defined'] == False:
                print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
            else:
                print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                    ' ... [ ' + okColor + 'OK' + endColor + ' ]')

    https = foo.test_https(url)
    if https['supported']:
        print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

    if https['certvalid']:
        print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')


    if foo.test_http_to_https(url, 5):
        print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
    else:
        print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')



if __name__=="__main__":

	deleteTabels()

	fl = open(sys.argv[1], "r").readlines() 
    
	for line in fl:
		domain = line.strip()
		if is_valid_domain(domain):
			create_domains_table(domain)
			subdomains(domain)
			ssl_version_suported(domain)
            #secHead(domain)	
      