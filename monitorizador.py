#!/usr/bin/env python3

import datetime
import http.client
import ipaddress
import json
import logging
import logging.config
#import math
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import dns.resolver
import requests
#from ail_typo_squatting import runAll, subdomain
from bs4 import BeautifulSoup
from urllib.parse import urlparse

#cabeçalho com variaveis globais
#interface masscan pode ser mudada
masscan_interface = "enp0s3"
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

#--------Ip's e Gamas-------------
#----auxiliares-----
def validate_ip_address(addr):
    """Funcao que verifica se um ip eh valido"""
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def validate_network(addr):
    """Funcao que verifica se é uma rede valida

    Args:
        addr (string): rede a ser verificada

    Returns:
        _type_: boolean
    """
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except ValueError:
        return False

def is_private(addr):
    """Funcao que verifica se um Ip eh privado"""
    privado = ipaddress.ip_address(addr).is_private
    if privado:
        return privado
        
#---------------------------------------------------------

logconfig = { 
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': { 
        'standard': { 
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': { 
        'default': { 
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        },
    },
    'loggers': { 
        '': {
            'handlers': ['default'],
            'level': 'DEBUG',
            'propagate': True
        },
    } 
}

class ModelHost:
	def __init__(self, address, addrtype="ipv4", name=None):
		self.address = address
		self.addrtype = addrtype
		self.name = name
		self.ports = []

	def addport(self, port):
		if not isinstance(port, ModelPort):
			raise ValueError("port is not a ModelPort")

		self.ports.append(port)
		
	def __str__(self):
		ports = ', '.join([str(i) for i in self.ports])
		if self.name:
			return "{0}: {1} -> [{2}]".format(self.name, self.address, ports)

		return "{0} -> [{1}]".format(self.address, ports)

class ModelPort:
	def __init__(self, nr, proto="tcp", desc=None, state="open", ssl=False):
		self.nr = int(nr)
		self.proto = proto
		self.description = desc
		self.state = state
		self.ssl = ssl

	def __str__(self):
		return '{0}'.format(self.nr)


class ModelInfo:
	def __init__(self, bl):
		self.bl = bl

	def __str__(self):
		return '{0}'.format(self.bl)

#reverseIP Model TODO

class Importer:
	def __init__(self, source, database=tempfile.mktemp('-hosts.db')):
		self.logger = logging.getLogger(self.__class__.__name__)
		self.source = source
		self.database = database
		self.hosts = []
		self.__process__()

	def __process__(self):
		self.logger.error("Not implemented here...")
		raise NotImplementedError("import")

	def __store__(self):
		self.logger.info('Opening database: {0}'.format(self.database))
		conn = sqlite3.connect(self.database)
		conn.execute("PRAGMA foreign_keys = on")
		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Host` (
				`HostID` INTEGER PRIMARY KEY AUTOINCREMENT,
				`Address`	TEXT,
				`Name`	TEXT
		);
		''')

		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Port` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				HostID   INTEGER,
				`Time` TIMESTAMP,
				`Port`	INTEGER,
				`Protocol`	TEXT,
				`Description`	TEXT,
				`State`	TEXT,
				`SSL`	INTEGER,
				FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
		);
		''')

		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Time` (
				HostID   INTEGER,
				`Time` TIMESTAMP,
				PRIMARY KEY (HostID, `Time`),
				FOREIGN KEY (HostID) REFERENCES `Host`(`HostID`)
		);
		''')

		for host in self.hosts:
			sql = 'INSERT INTO `Host`(`Address`,`Name`) VALUES (?,?)'
			values = (host.address, host.name)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
			sql='SELECT HostID FROM `Host` WHERE `Address`=?'
			values = (host.address,)
			
			host_id = conn.execute(sql, values).fetchall()[0][0]
		
			#tabela time
			sql = 'INSERT INTO `Time`(HostID, `Time`) VALUES (?,?)'
			date = datetime.datetime.now()
			values = (host_id, date)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
					
			for port in host.ports:
				sql = 'INSERT INTO `Port` VALUES (?,?,?,?,?,?,?,?)'
				values = (None, host_id, date, port.nr, port.proto, port.description, port.state, port.ssl)
				self.logger.debug(sql)
				self.logger.debug(values)
				conn.execute(sql, values)
				
		conn.commit()
		

class NmapXMLInmporter(Importer):
	def __process__(self, source=None):
		if not source:
			source = self.source
		self.logger.debug("Processing {0}".format(source))

		soup = BeautifulSoup(open(source).read(), "xml")
		hosts = soup.find_all("host")

		for host in hosts:
			if host.status['state'] == 'up':
				hostnames = host.find_all("hostname", attrs={'type':'user'})
				if hostnames:
					h = ModelHost(host.address['addr'], name=hostnames[0]['name'])
				else:
					h = ModelHost(host.address['addr'])
				ports = host.find_all("port")

				for port in ports:
					#So permite open ports e nao filtered
					if "open" in port.state['state'] and "open|filtered" not in port.state['state']:
						if port.service:
							ssl = 'tunnel' in port.service.attrs and port.service['tunnel'] == 'ssl'		
							p = ModelPort(nr=port['portid'], proto=port['protocol'], desc=port.service['name'], ssl=ssl, state=port.state['state'])
						else:
							p = ModelPort(nr=port['portid'], proto=port['protocol'], state=port.state['state'])
						h.addport(p)
			else:
				h = ModelHost(host.address['addr'])

			self.logger.debug(h)
			self.hosts.append(h)
		self.__store__()


def ipScan(ipAddr):
    hosts = {}
    ports = "ports"

    #Atencao ah interface
    #command = "masscan " + ipAddr + " --rate=1500 -p0-65535 -e tun0 -oJ mscan.json"
    command = "masscan " + ipAddr + " --rate=1500 -p0-65535 -e "+ masscan_interface +" -oJ mscan.json"

    print("[+] Running the masscan enumeration:  %s" % command)
    os.system(command)

    f = open("mscan.json", "r")
    lines = f.readlines()
    f.close()
    if len(lines) == 0:
        simplefile = open(ip + ".xml","w+")
        simplefile.write("<host><status state=" + "\u0022" + "down" + "\u0022" "/> <address addr=" + "\u0022" + ip + "\u0022" + "warning=" + "\u0022" + "No ports found" + "\u0022" "/>" +"</host>")
        simplefile.close()
        
    else:
        data = lines[len(lines)-2]
        temp = list(data) 
        temp[len(data)-2] = ""
        data = ''.join(temp)
        lines[len(lines)-2] = data

        with open("mscan.json", "w") as jsonfile:
            jsonfile.writelines(lines)
        
        f = open("mscan.json", "r")
        loaded_json = json.load(f)
    
        for x in loaded_json:
            port = x["ports"][0]["port"]
            print(port)
            ip_addr = x["ip"]
            
            #melhorar codigo
            try:
                hosts[ip_addr]
            except KeyError:
                hosts[ip_addr] = {}
            try:
                hosts[ip_addr][ports]
            except KeyError:
                hosts[ip_addr][ports] = []

            if not port in hosts[ip_addr][ports]:
                hosts[ip_addr][ports].append(port)

        text_file = open("scans.txt", 'w')

        hcount = 0
        cmds_list = []

        for h in hosts:
            port_str = "-p"
            print("[+] Host: %s" % h)
          
            text_file.write("%s" % h)
            hcount+=1
            tstring = h
            tstring += str(':-p')
            for p in hosts[h]["ports"]:
                porto = str(p)
                print("    [+] Port: %s" % porto)
                port_str += porto 
                port_str += str(",")
                tstring += porto 
                tstring += str(",")
            tmp_str = port_str[:-1]
            text_file.write(" %s\n" % tmp_str)

            tstring = tstring[:-1]
            cmds_list.append(tstring)
     
        print("[+] Created %d scan lines in text file: 'scans.txt'" % hcount) 
      
        text_file.close()

        nmap_base = "sudo nmap -sS -sV -sC "
        for cmd in cmds_list:
            tmp1 = cmd.split(':')
            host = tmp1[0]
            ports = tmp1[1]
        
            full_nmap_cmd = nmap_base + host + " " + ports + " " + "-oX " + host + ".xml"
            
            print("[+] Running nmap command: %s" % full_nmap_cmd)
            os.system(full_nmap_cmd)

def starter(ip):
	
	logging.config.dictConfig(logconfig)
	logger = logging.getLogger()
	logger.info("Nmap parsing '{0}'".format(ip))

	#nome da base de dados pode ser alterado
	db = database_name
	NmapXMLInmporter(ip, database=db)

#com problemas. nao apresenta toda a infromacao
def reverseIpLookup(ip_address_obj):
    """Funcao reverseIpLookup

    Args:
        ip_address_obj (string): ip a analisar
    """
    db = database_name
    conn = sqlite3.connect(db)

    conn.execute('''
            CREATE TABLE IF NOT EXISTS `ReverseIP` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                HostID INTEGER,
                `ReverseIP`	TEXT,
                `Time` TIMESTAMP,
                FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
        );
        ''')

    #source = "reverseIP_"+ip+".xml"

    sql='SELECT HostID FROM `Host` WHERE `Address`=?'
    values = (ip,)

    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT `Time` FROM `Time` WHERE HostID=?'

    host_id=host_id[0][0]
    values=(host_id,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]
    
    if not ipaddress.ip_address(ip_address_obj).is_private:
       # types = ["aaaa", "mx", "cname"]
        types = ["any"]

        for t in types:
            command = "nslookup -type=" + t + " " + ip_address_obj
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
      
            if error:
                msg = "error"
            else:
                s = output.decode("utf=8")
                print(s)
                h=s.split("=")
                x=h[1].split("\n",1)
                y=x[0]
                l = len(y)
                msg = y[:l-1]
              
                values = (None, host_id, str(msg),time)
                sql = 'INSERT INTO `ReverseIP` VALUES (?,?,?,?)'
            
                conn.execute(sql, values)
                conn.commit()

                print(msg)
    else:
        msg = "Private IP"

        values = (None, host_id, str(msg),time)
        sql = 'INSERT INTO `ReverseIP` VALUES (?,?,?,?)'
    
        conn.execute(sql, values)
        conn.commit()

        print(msg)


def blacklistedIP(badip):
    """Funcao que verifica se um IP esta Blacklisted

    Args:
        badip (String): Ip no formato de string
    """

    db = database_name
    conn = sqlite3.connect(db)

    conn.execute('''
            CREATE TABLE IF NOT EXISTS `Blacklist` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                HostID INTEGER,
                `Blacklisted`	TEXT,
                `Time` TIMESTAMP,
                FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
        );
        ''')

    sql='SELECT HostID FROM `Host` WHERE `Address`=?'
    values = (badip,)
    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT `Time` FROM `Time` WHERE HostID=?'

    host_id=host_id[0][0]
    values=(host_id,)
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

    for bl in bls:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
            my_resolver.timeout = 2
            my_resolver.lifetime = 2
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print((badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))

            blist = str(bl)
            sql = 'INSERT INTO `Blacklist`(ID, HostID, `Blacklisted`, `Time`) VALUES (?,?,?,?)'
            values = (None, host_id, blist, time)
            conn.execute(sql, values)
            conn.commit()
            
        except dns.resolver.NXDOMAIN:
            print(badip + ' is not listed in ' + bl)
                
        except dns.resolver.Timeout:
            print('WARNING: Timeout querying ' + bl)
                        
        except dns.resolver.NoNameservers:
            print('WARNING: No nameservers for ' + bl)
                
        except dns.resolver.NoAnswer:
            print('WARNING: No answer for ' + bl)
        
            
def ipRangeCleaner(ip):
    """Funcao que estende uma gama de Ip's

    Args:
        ip (String): recebe um ip no formato de string
    """
   
    f = open("cleanIPs.txt", "a") 
    txt = "\n".join([str(x) for x in ipaddress.ip_network(ip).hosts()])+"\n"
    f.write(txt)
    f.close()



#################################################################
#-------------------Dominios-----------------
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

    db = database_name
    conn = sqlite3.connect(db)

    subdomains = []
    target = clear_url(domains)
    #output = domains+".txt"
 
    req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))
    i = 0
    
    if req.status_code != 200 and i < 10:
        print("[X] Information not available! Running...") 
        subdomains_finder(domains)
        i = i+1
    
    if (req.status_code == 200):
        conn.execute('''
                CREATE TABLE IF NOT EXISTS `Subdomains` (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Domain_ID INTEGER,
                    Subdomain TEXT,
                    StartDate TEXT,
                    EndDate TEXT,
                    Country TEXT,
                    CA TEXT,
                    Time TIMESTAMP,
                    
                    FOREIGN KEY (Domain_ID, Time) REFERENCES `DomainTime`(DomainID, `Time`)
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
                    
                    print("[+] Subdominio: "+ subdomain+" [+]")
                    print("subdomain: "+subdomain+" ,"+"not_before: "+ startDate +", "+"not_after: "+endDate+","+"country: "+country+", "+"issuer_name: "+ca) 
                    print("[+] Cabecalhos de Seguranca: "+subdomain+" [+]")
                    secHead(subdomain)
                    print("\n")

                    sql = 'SELECT ID FROM Domains WHERE Domains=?'
                    values = (domains,)
                    domID = conn.execute(sql, values).fetchall()
                    domID = domID[0][0]
                    
                    sql='SELECT `Time` FROM `DomainTime` WHERE DomainID=?'
                    values=(domID,)
                    time = conn.execute(sql, values).fetchall()
                    time = time[0][0]

                    sql = 'INSERT INTO `Subdomains`(ID, Domain_ID, Subdomain, StartDate, EndDate, Country, CA, Time) VALUES (?,?,?,?,?,?,?,?)'
                    values = (None, domID, subdomain, startDate, endDate, country, ca, time )
                    conn.execute(sql, values)
                    conn.commit()

        print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):
    """Funcao que verica que versoes SSL/TLS estao a ser usadas"""
    
    db = database_name
    conn = sqlite3.connect(db)

    conn.execute('''
            CREATE TABLE IF NOT EXISTS `SSL/TLS` (
                ID INTEGER PRIMARY KEY,
                in_use TEXT,
                SSLv2 TEXT,
                SSLv3 TEXT,
                TLSv1 TEXT,
                TLSv1_1 TEXT,
                TLSv1_2 TEXT,
                TLSv1_3 TEXT,
                `Time` TIMESTAMP,
                FOREIGN KEY (ID, `Time`) REFERENCES `DomainTime`(ID, `Time`)
        );
        ''')

    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443)) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
            if ssock.version():

                in_use = ssock.version()
                
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
                #in_use = ssock.version()
                
                
                sql='SELECT ID FROM `Domains` WHERE `Domains`=?'
                values = (domain,)

                host_id = conn.execute(sql, values).fetchall()

                sql='SELECT `Time` FROM `Time` WHERE HostID=?'

                host_id=host_id[0][0]
                values=(host_id,)
                time = conn.execute(sql, values).fetchall()
                time = time[0][0]
                
                sql = 'INSERT INTO `SSL/TLS`(ID, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, `Time`) VALUES (?,?,?,?,?,?,?,?,?)'
                values = (None, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, time)
                
                conn.execute(sql, values)
                conn.commit()
                
                #print(ssock.getpeercert(binary_form=False))
            else:
                print("Not found")

#verificar com outros outputs 
def create_domains_table(domain):
    """Funcao que cria a tabelas dos dominios"""
    
    db = database_name
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

def create_domain_table_time(domain):
    """Funcao para criar a tabela com os tempos associados 
    a cada dominio"""

    db = database_name
    conn = sqlite3.connect(db)

    conn.execute('''
        CREATE TABLE IF NOT EXISTS `DomainTime` (
            DomainID   INTEGER,
            `Time` TIMESTAMP,
            PRIMARY KEY (DomainID, `Time`),
            FOREIGN KEY (DomainID) REFERENCES `Domains`(`ID`)
    );
    ''')
    
    sql='SELECT ID FROM `Domains` WHERE `Domains`=?'
    values = (domain,)

    domid = conn.execute(sql, values).fetchall()
    domid=domid[0][0]

    sql = 'INSERT INTO `DomainTime`(DomainID, `Time`) VALUES (?,?)'
    date = datetime.datetime.now()
    values = (domid, date)
    conn.execute(sql, values)
    conn.commit()

'''
#Com dnstwist
def typo_squatting(d):
    data = dnstwist.run(domain=d, registered=True, format='list')
    print(data)
'''

#TODO melhorar squatting com ail-typo-squatting

def blacklisted(domain):
    """Funcao que procura dominios em blacklists"""

    db = database_name
    conn = sqlite3.connect(db)
	
    #adicionar Time (TimeStamp) como FK
    conn.execute('''
            CREATE TABLE IF NOT EXISTS `BlacklistDomains` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                DomainID INTEGER,
                Blacklist TEXT,
                `Time` TIMESTAMP,

                FOREIGN KEY (DomainID, `Time`) REFERENCES `DomainTime`(ID, `Time`)
                );
        ''')
	
    sql='SELECT ID FROM `Domains` WHERE `Domains`=?'
    values = (domain,)
    domid = conn.execute(sql, values).fetchall()
    domid=domid[0][0]

    sql='SELECT `Time` FROM `DomainTime` WHERE DomainID=?'
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
    result =  my_resolver.query(domain, 'A')
    for ipval in result:
        ip = ipval.to_text()

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
            sql = 'INSERT INTO `BlacklistDomains`(ID, DomainID, Blacklist, Time) VALUES (?,?,?,?)'
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
        #protocol = parsed[0]
        hostname = parsed[1]
        #path = parsed[2]
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

            #set to lowercase before the check
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
   
    db = database_name
    con = sqlite3.connect(db)

    con.execute('''
        CREATE TABLE IF NOT EXISTS `SecurityHeaders` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Subdomain_ID INTEGER,
            Header TEXT,
            Info TEXT,
            Status TEXT,
            `Time` TIMESTAMP,
            
            FOREIGN KEY (Subdomain_ID, `Time`) REFERENCES `DomainTime`(DomainID, `Time`)
            );
        ''')

    sql='SELECT ID FROM `Subdomains` WHERE `Subdomain`=?'
    values = (domain,)
    subdomId = con.execute(sql, values).fetchall()
    subdomId = subdomId[0][0]

    sql='SELECT ID FROM `Domains` WHERE `Domains`=?'
    values = (domain,)
    domid = con.execute(sql, values).fetchall()
    domid=domid[0][0]

    sql='SELECT `Time` FROM `DomainTime` WHERE DomainID=?'
    values=(domid,)
    time = con.execute(sql, values).fetchall()
    time = time[0][0]

    url = domain
    redirects = 6

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided

    headers = SecurityHeaders().check_headers(url, redirects)

   # if not headers:
   #     print ("Failed to fetch headers, exiting...")
    #    sys.exit(1)
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
                    sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, info, status, time )
                    con.execute(sql, values)
                    con.commit()

                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + warnColor + 'WARN' + endColor + ' ]')
                    status = "WARN"
                    sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, value['contents'], status, time )
                    con.execute(sql, values)
                    con.commit()

            elif value['warn'] == 0:
                if not value['defined']:
                    print('Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]')
                    status = "OK"
                    info = "is missing"
                    sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, info, status, time )
                    con.execute(sql, values)
                    con.commit()
                else:
                    print('Header \'' + header + '\' contains value \'' + value['contents'] + '\'' + \
                        ' ... [ ' + okColor + 'OK' + endColor + ' ]')
                    status = "OK"
                    sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
                    values = (None, subdomId, header, value['contents'], status, time )
                    con.execute(sql, values)
                    con.commit()

        https = SecurityHeaders().test_https(url)
        if https['supported']:
            print('HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]')
            head = "HTTPS supported"
            status = "OK"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTPS supported"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()

        if https['certvalid']:
            print('HTTPS valid certificate ... [ ' + okColor + 'OK' + endColor + ' ]')
            status = "OK"
            head = "HTTPS valid certificate"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTPS valid certificate ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTPS valid certificate"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()

        if SecurityHeaders().test_http_to_https(url, 5):
            print('HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]')
            status = "OK"
            head = "HTTP -> HTTPS redirect"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
        else:
            print('HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]')
            status = "FAIL"
            head = "HTTP -> HTTPS redirect"
            sql = 'INSERT INTO `SecurityHeaders`(ID, Subdomain_ID, Header, Info, Status, `Time`) VALUES (?,?,?,?,?,?)'
            values = (None, subdomId, head, None, status, time )
            con.execute(sql, values)
            con.commit()
    except:
          print("Failed to fetch headers")     
        
        
def deleteTabels():
    """Funcao que apaga todas as tabelas da base de dados"""
    
    db = database_name
    conn = sqlite3.connect(db)
    conn.execute(''' DROP TABLE IF EXISTS `BlacklistDomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `SecurityHeaders`;''')
    conn.execute(''' DROP TABLE IF EXISTS `SSL/TLS`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Subdomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `DomainTime`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Blacklist`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Port`;''')
    conn.execute(''' DROP TABLE IF EXISTS `ReverseIP`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Host`;''')

    conn.commit()
    

if __name__=="__main__":

    deleteTabels()
    
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    else:
        print("The file -> cleanIPs.txt <- does not exist!")
    
                       
    fips = open(sys.argv[1], "r").readlines() 
    fdominio = open(sys.argv[2], "r").readlines() 

    if len(fips) != 0:
        for lineIP in fips:
            h=lineIP.strip()
            ipRangeCleaner(h)

        cf = open("cleanIPs.txt", "r").readlines()
        for l in cf:
            ip = l.strip()
            if validate_ip_address(ip):
                f = ip+".xml"
                ipScan(ip)
                starter(f)
                #reverseIpLookup(ip)
                blacklistedIP(ip)
                os.remove(ip+".xml")
    else:
        print("Ficheiro de ips sem conteudo")
                
    if len(fdominio) != 0: 
        for line in fdominio:  
            domain = line.strip()
            if is_valid_domain(domain):
                create_domains_table(domain)
                create_domain_table_time(domain)
                subdomains_finder(domain)
                ssl_version_suported(domain)
                secHead(domain)
                #typo_squatting(domain)
                #dnsresolve(domain)
                blacklisted(domain)
    else:
        print("Ficheiro de dominios sem conteudo")

    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    if os.path.exists("scans.txt"):
        os.remove("scans.txt")
    if os.path.exists("mscan.json"):
        os.remove("mscan.json")
    else:
        print("All files deleted!")
    
    #fips.close()
    #fdominio.close()
    