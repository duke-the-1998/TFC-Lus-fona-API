#!/usr/bin/env python3

import datetime
import http.client
import re
import socket
import sqlite3
import ssl
import sys
import dns.resolver
import requests

from crtsh import crtshAPI
from urllib.parse import urlparse
from crtsh_cert_info import check_cert

#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"

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
    return False

#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + "\n")
###################################################


def simplify_list(lista):
    """ list of list to list, removing duplicates
    """
    flat_list = [item for sublist in lista for item in sublist]
    return list(set(flat_list))

    
def subdomains_finder(domains):
    
    db = database_name
    conn = sqlite3.connect(db)
    
    subdomains = list()
    target = clear_url(domains)

    req_json = crtshAPI().search(target)
    
    for value in req_json:
        subdomains.append(str(value['name_value']).split("\n"))
        
    subdomains_flat = simplify_list(subdomains)
    
    for subdomain in subdomains_flat:
        
        result_dict = check_cert(subdomain)
        
        start_date = result_dict.get('start_date')
        valid_until = result_dict.get('valid_until')
        days_left = result_dict.get('reason')
        org_name = result_dict.get('org_name')
        
        print("[+] domain: " + subdomain + ", start_date: " + start_date + ", valid_until: " + valid_until + ", days_left: " + days_left + ", org_name: " + org_name + " [+]\n")
        
       
        sql = 'SELECT ID FROM domains WHERE Domains=?'
        values = (domains,)
        domID = conn.execute(sql, values).fetchall()
        domID = domID[0][0]
        
        sql='SELECT `Time` FROM `domain_time` WHERE DomainID=?'
        values=(domID,)
        time = conn.execute(sql, values).fetchall()
        time = time[0][0]

        sql = 'INSERT INTO `subdomains`(ID, Domain_ID, Subdomain, start_date, valid_until, days_left, org_name, Time) VALUES (?,?,?,?,?,?,?,?)'
        values = (None, domID, subdomain, start_date, valid_until, days_left, org_name, time )
        conn.execute(sql, values)
        
        conn.commit()
        
        print("[+] Cabecalhos de Seguranca: "+subdomain+" [+]\n")     
        secHead(subdomain, domains)
    
    

"""NOVA FUNCAO PARA PROCURAR SUBDOMINIOS
Usa a api hackertarget (dnsdumpster)
insere na BD subdomiois e dominios
"""
def subdomains_finder_dnsdumpster(domain):
    db = database_name
    conn = sqlite3.connect(db)
    
    try:
        DOMAINS = []
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        lines = api.text.split("\n")
        if '' in lines:
            lines.remove('')
            for line in lines:
                    x = line.split(',')
                    subdomain = x[0]
                    ip = x[1]
                    
                    print("\n[+] Subdominio: "+ subdomain+ " IP: " + ip+ " [+]")
                    print("\n")

                    sql = 'SELECT ID FROM domains WHERE Domains=?'
                    values = (domain,)
                    domID = conn.execute(sql, values).fetchall()
                    domID = domID[0][0]
                    
                    sql='SELECT `Time` FROM `domain_time` WHERE DomainID=?'
                    values=(domID,)
                    time = conn.execute(sql, values).fetchall()
                    time = time[0][0]

                    sql = 'INSERT INTO `subdomains_dump`(ID, Domain_ID, Subdomain, ip, Time) VALUES (?,?,?,?,?)'
                    values = (None, domID, subdomain, ip, time )
                    conn.execute(sql, values)
                    
                    conn.commit()
                    
                    print("[+] Cabecalhos de Seguranca: "+subdomain+" [+]\n")     
                    secHead(subdomain, domain)
    
    except requests.Timeout:
        return 'Connection Timeout: Retry Again'
    except requests.ConnectionError:
        return 'Connection Lost: Retry Again'
    except requests.RequestException:
        return 'Connection Failed: Retry Again'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
    
#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):
    """Funcao que verica que versoes SSL/TLS estao a ser usadas"""
    
    db = database_name
    conn = sqlite3.connect(db)

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
            if ssock.version():
                print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=hostname))
                in_use = ssock.version()
                print("in_use: "+in_use)
                print("SSLv2: "+str(ssl.HAS_SSLv2))
                print("SSLv3: "+str(ssl.HAS_SSLv3))
                print("TLSv1: "+str(ssl.HAS_TLSv1))
                print("TLSv1_1: "+str(ssl.HAS_TLSv1_1))
                print("TLSv1_2: "+str(ssl.HAS_TLSv1_2))
                print("TLSv1_3: "+str(ssl.HAS_TLSv1_3))

                TLSv1_3 = str(ssl.HAS_TLSv1_3)
                TLSv1_2 = str(ssl.HAS_TLSv1_2)
                TLSv1_1 = str(ssl.HAS_TLSv1_1)
                TLSv1 = str(ssl.HAS_TLSv1)
                SSLv2 = str(ssl.HAS_SSLv2)
                SSLv3 = str(ssl.HAS_SSLv3)
                
                sql = 'SELECT ID FROM `domains` WHERE `Domains`=?'
                values = (hostname,)
                host_id = conn.execute(sql, values).fetchall()

                sql = 'SELECT `Time` FROM `domain_time` WHERE DomainID=?'
                host_id=host_id[0][0]
                values=(host_id,)
                time = conn.execute(sql, values).fetchall()
                time = time[0][0]
                
                sql = 'INSERT INTO `ssl_tls`(ID, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, `Time`) VALUES (?,?,?,?,?,?,?,?,?)'
                values = (None, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, time)
                
                conn.execute(sql, values)
                conn.commit()
                
            else:
                print("Not found")
    except:
         print("[!] DNS don't exist or maybe is down [!]")
   

#verificar com outros outputs 
def create_domains_table(domain):
    """Funcao que cria a tabelas dos dominios"""
    
    db = database_name
    conn = sqlite3.connect(db)

    sql = 'INSERT INTO `domains`(ID, Domains) VALUES (?,?)'
    values = (None, domain)

    conn.execute(sql, values)
    conn.commit()

def create_domain_table_time(domain):
    """Funcao para criar a tabela com os tempos associados 
    a cada dominio"""

    db = database_name
    conn = sqlite3.connect(db)
    
    sql='SELECT ID FROM `domains` WHERE `Domains`=?'
    values = (domain,)
    
    domid = conn.execute(sql, values).fetchall()
    domid=domid[0][0]

    sql = 'INSERT INTO `domain_time`(DomainID, `Time`) VALUES (?,?)'
    date = datetime.datetime.now()
    values = (domid, date)
    conn.execute(sql, values)
    conn.commit()


def blacklisted(domain):
    """Funcao que procura dominios em blacklists"""
    
    db = database_name
    conn = sqlite3.connect(db)
	
    sql='SELECT ID FROM `domains` WHERE `Domains`=?'
    values = (domain,)
    domid = conn.execute(sql, values).fetchall()
    domid=domid[0][0]

    sql='SELECT `Time` FROM `domain_time` WHERE DomainID=?'
    values=(domid,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]

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
    try:
        #result =  my_resolver.query(domain, 'A')
        #print("###########################" + result)
        #for ipval in result:
         #   ip = ipval.to_text()
        ip = socket.gethostbyname(domain) 
        
        for bl in bls:
            try:
                #my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(ip).split("."))) + "." + bl
                my_resolver.timeout = 2
                my_resolver.lifetime = 2
                answers = my_resolver.query(query, "A")
                answer_txt = my_resolver.query(query, "TXT")
                print((ip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))

                blist = str(bl)
                sql = 'INSERT INTO `blacklist_domains`(ID, DomainID, Blacklist, Time) VALUES (?,?,?,?)'
                values = (None, domid, blist, time)
                conn.execute(sql, values)
                conn.commit()
                
            except dns.resolver.NXDOMAIN:
                print(domain + ' is not listed in ' + bl)
                    
            except dns.resolver.Timeout:
                print('WARNING: Timeout querying ' + bl)
                            
            except dns.resolver.NoNameservers:
                print('WARNING: No nameservers for ' + bl)
                
            except dns.resolver.NoAnswer:
                print('WARNING: No answer for ' + bl)
            
            except UnboundLocalError:
                print("Failed to resolve")
                
            except:
                print("Something wrong")
    except:
        print("Failed to resolve")
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

        if header == 'x-frame-options' and contents.lower() in ['deny', 'sameorigin']:
            warn = 0

        if header == 'strict-transport-security':
            warn = 0

        if header == 'content-security-policy':
            warn = 0

        if header == 'access-control-allow-origin' and contents != '*':
            warn = 0

        if header.lower() == 'x-xss-protection' and contents.lower() in ['1', '1; mode=block']:
            warn = 0

        if header == 'x-content-type-options' and contents.lower() == 'nosniff':
            warn = 0
        
        if header == 'x-powered-by' or header == 'server' and len(contents) <= 1:
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
        except socket.timeout:
            print('HTTP request failed: Timeout')
            return False
        except:
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
            conn = http.client.HTTPConnection(hostname, timeout=10)
        elif protocol == 'https':
            # on error, retry without verifying cert
            # in this context, we're not really interested in cert validity
            ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(hostname, context = ctx, timeout=10)
        else:
            """ Unknown protocol scheme """
            print("ERROR: Unknown protocol")
            return {}
       
        #atencao a este try!!!
        #adicionar timeout 10segs
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
            
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
            
        except socket.gaierror:
            print('HTTP request failed')
            #return False
        except socket.timeout:
            print('HTTP request failed, socket timeout')
        except ConnectionRefusedError:
            print('HTTP request failed. ConnectionRefusedError.')
        except TimeoutError:
            print('HTTP request failed. TimeoutError')
        except ConnectionResetError:
            print('HTTP request failed. Connection Reset Error by peer')
        except ConnectionAbortedError:
            print('HTTP request failed. Connection Aborted Error')
        except:
            print('ERROR')
           # return False
       
       
def secHead(subdomain, domain):
    """Funcao que insere as informacoes sobre os cabecalhos de 
    seguranca na base de dados

    Args:
        domain (string): dominio no formato de string lido do 
        do ficheiro dominios.txt
    """
   
    db = database_name
    con = sqlite3.connect(db)
    
    sql='SELECT ID FROM `subdomains` WHERE `Subdomain`=?'
    #sql='SELECT ID FROM `subdomains_dump` WHERE `Subdomain`=?'
    values = (subdomain,)
    subdomId = con.execute(sql, values).fetchall()
    subdomId = subdomId[0][0]

    sql='SELECT ID FROM `domains` WHERE `Domains`=?'
    values = (domain,)
    domid = con.execute(sql, values).fetchall()
    domid=domid[0][0]
    
    sql='SELECT `Time` FROM `domain_time` WHERE DomainID=?'
    values=(domid,)
    time = con.execute(sql, values).fetchall()
    time = time[0][0]

    url = subdomain
    redirects = 6

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided

    headers = SecurityHeaders().check_headers(url, redirects)

    try:
        okColor = '\033[92m'
        warnColor = '\033[93m'
        endColor = '\033[0m'
        for header, value in headers.items():
            if value['warn'] == 1:
                if not value['defined']:
                    print('Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]')
                    status = "WARN"
                    info = "is missing"
                    sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, info, status, time )
                    con.execute(sql, values)
                    con.commit()

                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
                    status = "WARN"
                    sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, value['contents'], status, time )
                    con.execute(sql, values)
                    con.commit()

            elif value['warn'] == 0:
                if not value['defined']:
                    print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
                    status = "OK"
                    info = "is missing"
                    sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, info, status, time )
                    con.execute(sql, values)
                    con.commit()
                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + okColor + 'OK' + endColor + ' ]')
                    status = "OK"
                    sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, value['contents'], status, time )
                    con.execute(sql, values)
                    con.commit()

        https = SecurityHeaders().test_https(url)
        if https['supported']:
            print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
            head = "HTTPS supported"
            status = "OK"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTPS supported"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()

        if https['certvalid']:
            print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
            status = "OK"
            head = "HTTPS valid certificate"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTPS valid certificate"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()

        if SecurityHeaders().test_http_to_https(url, 5):
            print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
            status = "OK"
            head = "HTTP -> HTTPS redirect"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTP -> HTTPS redirect"
            sql = 'INSERT INTO `security_headers`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
            
    except TimeoutError:
        print("TimeOut")
    except ConnectionError:
        print("Connection Error")
    except:
        print("Failed to fetch headers")
             
