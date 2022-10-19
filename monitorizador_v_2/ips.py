#!/usr/bin/env python3

import datetime
import ipaddress
import json
import logging
import logging.config
import os
import sqlite3
import subprocess
import tempfile
import dns.resolver
from bs4 import BeautifulSoup
from ip_models import ModelHost, ModelPort

#cabeçalho com variaveis globais
#interface masscan pode ser mudada
#masscan_interface = "enp0s3"
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

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

def ipRangeCleaner(ip):
    """Funcao que estende uma gama de Ip's

    Args:
        ip (String): recebe um ip no formato de string
    """
   
    f = open("cleanIPs.txt", "a") 
    txt = "\n".join([str(x) for x in ipaddress.ip_network(ip).hosts()])+"\n"
    f.write(txt)
    f.close()

#---------------------------------------------------------

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

		for host in self.hosts:
			sql = 'INSERT INTO `host`(`Address`,`Name`) VALUES (?,?)'
			values = (host.address, host.name)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
   
			sql='SELECT HostID FROM `host` WHERE `Address`=?'
			values = (host.address,)
			host_id = conn.execute(sql, values).fetchall()[0][0]
		
			#tabela time
			sql = 'INSERT INTO `time`(HostID, `Time`) VALUES (?,?)'
			date = datetime.datetime.now()
			values = (host_id, date)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
					
			for port in host.ports:
				sql = 'INSERT INTO `port` VALUES (?,?,?,?,?,?,?,?)'
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


def ipScan(ipAddr, masscan_interface):
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
        simplefile = open(ipAddr + ".xml","w+")
        simplefile.write("<host><status state=" + "\u0022" + "down" + "\u0022" "/> <address addr=" + "\u0022" + ipAddr + "\u0022" + "warning=" + "\u0022" + "No ports found" + "\u0022" "/>" +"</host>")
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

    #source = "reverseIP_"+ip+".xml"

    sql='SELECT HostID FROM `host` WHERE `Address`=?'
    values = (ip_address_obj,)

    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT `Time` FROM `time` WHERE HostID=?'

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
                sql = 'INSERT INTO `reverse_ip` VALUES (?,?,?,?)'
            
                conn.execute(sql, values)
                conn.commit()

                print(msg)
    else:
        msg = "Private IP"

        values = (None, host_id, str(msg),time)
        sql = 'INSERT INTO `reverse_ip` VALUES (?,?,?,?)'
    
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

    sql='SELECT HostID FROM `host` WHERE `Address`=?'
    values = (badip,)
    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT `Time` FROM `time` WHERE HostID=?'

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
            sql = 'INSERT INTO `blacklist_ip`(ID, HostID, `Blacklisted`, `Time`) VALUES (?,?,?,?)'
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
        
