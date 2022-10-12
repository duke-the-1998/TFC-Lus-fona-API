#!/usr/bin/env python3

import http.client
import re
import socket
import ssl
import sys
import tempfile
import dns.resolver
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


#-------auxiliares-------------
def is_valid_domain(dominio):
    """Funcao auxiliar que recebe uma string e verifica se eh 
    um dominio valido

    Args:
        dominio (String): dominio no formato de string lido do 
        ficheiro dominios.txt

    Returns:
        Boolean: Retorna True se o dominio != None e se cumprir
        os requisitos da regex
    """
 
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
     
    p = re.compile(regex)
 	 
    if dominio != None and re.search(p, dominio):
        return True

#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + "\n")
		f.close()

def subdomains_finder(domains):

    subdomains = []
    target = clear_url(domains)
   
    req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))
    i = 0
    
    if req.status_code != 200 and i < 10:
        print("[X] Information not available! Running...") 
        subdomains_finder(domains)
        i = i+1

    if (req.status_code == 200):

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

                    print("[+] Subdominio: "+ subdomain+" [+]")
                    print("subdomain: "+subdomain+" ,"+"not_before: "+ startDate +", "+"not_after: "+endDate+","+"country: "+country+", "+"issuer_name: "+ca) 
                    print("[+] Cabecalhos de Seguranca: "+subdomain+" [+]")
                    secHead(subdomain)
                    print("\n")
                    
        print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):
    """Funcao que verica que versoes SSL/TLS estao a ser usadas"""

    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443)) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
            if ssock.version():

                in_use = ssock.version()
                print("in_use: "+in_use)
                print("SSLv2: "+str(ssl.HAS_SSLv2))
                print("SSLv3: "+str(ssl.HAS_SSLv3))
                print("TLSv1: "+str(ssl.HAS_TLSv1))
                print("TLSv1_1: "+str(ssl.HAS_TLSv1_1))
                print("TLSv1_2: "+str(ssl.HAS_TLSv1_2))
                print("TLSv1_3: "+str(ssl.HAS_TLSv1_3))
                
            else:
                print("Not found")


def blacklisted(domain):
    """Funcao que procura dominios em blacklists"""

    bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
       "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net","dnsbl.spfbl.net", "drone.abuse.ch", "drone.abuse.ch",
       "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
       "dyna.spamrats.com", "dynip.rothen.com",
       "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net",
       "korea.services.net", "misc.dnsbl.sorbs.net",
       "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
       "orvedb.aupads.org", "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
       "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
       "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
       "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
       "residential.block.transip.nl", "ricn.dnsbl.net.au",
       "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
       "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
       "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
       "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
       "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
       "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
       "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
       "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]

    my_resolver = dns.resolver.Resolver()
    result =  my_resolver.query(domain, 'A')
    for ipval in result:
        ip = ipval.to_text()

    for bl in bls:
        try:
            query = '.'.join(reversed(str(ip).split("."))) + "." + bl
            my_resolver.timeout = 2
            my_resolver.lifetime = 2
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print((ip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))
            
        except dns.resolver.NXDOMAIN:
            print(domain + ' is not listed in ' + bl)
                
        except dns.resolver.Timeout:
            print('WARNING: Timeout querying ' + bl)
                        
        except dns.resolver.NoNameservers:
            print('WARNING: No nameservers for ' + bl)
            
        except dns.resolver.NoAnswer:
            print('WARNING: No answer for ' + bl)

#----------------------------
class SecurityHeaders():
    """Classe com as funcoes sobre os cabecalhos de seguranca
    """
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
        hostname = parsed[1]
        sslerror = False
            
        conn = http.client.HTTPSConnection(hostname, context = ssl.create_default_context())
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
            conn = http.client.HTTPSConnection(hostname, timeout=5, context = ssl._create_stdlib_context())
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

        if protocol == 'http':
            conn = http.client.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print('HTTP request failed')
            return False

        #Follow redirect
        if res.status >= 300 and res.status < 400  and follow_redirects > 0:
            for header in headers:
                if header[0].lower() == 'location':
                    return self.test_http_to_https(header[1], follow_redirects - 1)

        return False

    def check_headers(self, url, follow_redirects = 0):
        """funcao que procura informacao sobre os cabecalhos de seguranca"""
            
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
        if protocol == 'http':
            conn = http.client.HTTPConnection(hostname)
        elif protocol == 'https':
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
        if res.status >= 300 and res.status < 400  and follow_redirects > 0:
            for header in headers:
                if header[0].lower() == 'location':
                    redirect_url = header[1]
                    if not re.match('^https?://', redirect_url):
                        redirect_url = protocol + '://' + hostname + redirect_url
                    return self.check_headers(redirect_url, follow_redirects - 1)

        for header in headers:
            
            headerAct = header[0].lower()
            
            if headerAct in retval:
        
                retval[headerAct] = self.evaluate_warn(headerAct, header[1])

        return retval
        

def secHead(domain):
    """Funcao que insere as informacoes sobre os cabecalhos de 
    seguranca na base de dados

    Args:
        domain (string): dominio no formato de string lido do 
        do ficheiro dominios.txt
    """

    url = domain
    redirects = 6

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided

    headers = SecurityHeaders().check_headers(url, redirects)

    #if not headers:
       # print ("Failed to fetch headers...")
      #  pass
        
    try:
        okColor = '\033[92m'
        warnColor = '\033[93m'
        endColor = '\033[0m'
        for header, value in headers.items():
            if value['warn'] == 1:
                if not value['defined']:
                    print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')

                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')

            elif value['warn'] == 0:
                if not value['defined']:
                    print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
                
                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + okColor + 'OK' + endColor + ' ]')

        https = SecurityHeaders().test_https(url)
        if https['supported']:
            print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
        
        else:
            print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')

        if https['certvalid']:
            print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
            
        else:
            print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
        
        if SecurityHeaders().test_http_to_https(url, 5):
            print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
        
        else:
            print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
    except:
        print("Failed to fetch headers")        

if __name__=="__main__":

    fdominio = open(sys.argv[1], "r").readlines() 
     
    for line in fdominio:  
        domain = line.strip()
        if is_valid_domain(domain):
            print("[+] DOMINIO: " + domain + " [+]")
            subdomains_finder(domain)
            ssl_version_suported(domain)
            secHead(domain)
            blacklisted(domain)
            print("\n")
            