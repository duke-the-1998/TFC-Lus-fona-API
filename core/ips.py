#!/usr/bin/env python3

import datetime
import ipaddress
import json
import logging
import logging.config
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import dns.resolver
from bs4 import BeautifulSoup
from core.ip_models import ModelHost, ModelPort

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
        cleanaddr = "".join(addr.split())

        ipaddress.ip_address(cleanaddr)
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
    return ipaddress.ip_address(addr).is_private

def ip_range_cleaner(ip):
    """Funcao que estende uma gama de Ip's
    Args:
        ip (String): recebe um ip no formato de string
    """
    clean_ip = "".join(ip.split())
    with open("cleanIPs.txt", "a") as f:
        txt = "\n".join([str(x) for x in ipaddress.ip_network(clean_ip).hosts()])+"\n"
        f.write(txt)

    
#---------------------------------------------------------

class Importer:
    def __init__(self, source, db_conn):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.source = source
        self.db_conn = db_conn
        self.hosts = []
        self.__process__()

    def __process__(self):
        self.logger.error("Not implemented here...")
        raise NotImplementedError("import")

    def __store__(self):
        conn = self.db_conn

        for host in self.hosts:
            try:
                sql = 'INSERT INTO `host`(`host_id`, `address`,`Name`) VALUES (?,?,?)'
                values = (None, host.address, host.name)
                conn.execute(sql, values)
            except:
                print("Valor na base de dados")
    
            sql='SELECT host_id FROM `host` WHERE `address`=?'
            values = (host.address,)
            host_id = conn.execute(sql, values).fetchall()[0][0]
        
            sql = 'INSERT INTO `ip_time`(`host_id`, `time`) VALUES (?,?)'
            date = datetime.datetime.now()
            values = (host_id, date)
            conn.execute(sql, values)
                    
            for port in host.ports:
                sql = 'INSERT INTO `port` VALUES (?,?,?,?,?,?,?,?)'
                values = (None, host_id, date, port.nr, port.proto, port.description, port.state, port.ssl)
                conn.execute(sql, values)
                
        conn.commit()
        

class NmapXMLInmporter(Importer):
    def __process__(self, source=None):
        if not source:
            source = self.source

        soup = BeautifulSoup(open(source).read(), "xml")
        hosts = soup.find_all("host")

        for host in hosts:
            if host.status['state'] == 'up':
                if hostnames := host.find_all("hostname", attrs={'type': 'user'}):
                    h = ModelHost(host.address['addr'], name=hostnames[0]['name'])
                else:
                    h = ModelHost(host.address['addr'])
                ports = host.find_all("port")

                for port in ports:
                    #So permite open ports e nao filtered
                    #if "open" in port.state['state'] and "open|filtered" not in port.state['state']:
                    if "open" in port.state['state'] or "open|filtered" in port.state['state']:
                        if port.service:
                            ssl = 'tunnel' in port.service.attrs and port.service['tunnel'] == 'ssl'		
                            p = ModelPort(nr=port['portid'], proto=port['protocol'], desc=port.service['name'], ssl=ssl, state=port.state['state'])
                        else:
                            p = ModelPort(nr=port['portid'], proto=port['protocol'], state=port.state['state'])
                        h.addport(p)
                    
            else:
                h = ModelHost(host.address['addr'])

            self.hosts.append(h)
        self.__store__()


def ip_scan(ipAddr, masscan_interface, attempt=0):
    
    hosts = {}
    ports = "ports"
    masscan_outfile = "mscan.json"


    command = f"masscan {ipAddr} --rate=1500 -p0-65535 -e {masscan_interface} -oJ {masscan_outfile}"

    print(
        f"[+] Running the masscan enumeration:  {ipAddr} for iface {masscan_interface}"
    )
    os.system(command)


    with open(masscan_outfile, "r") as f:
        lines = f.readlines()

    if not lines:
        with open(f"{ipAddr}.xml", "w+") as simplefile:
            simplefile.write("<host><status state=" + "\u0022" + "down" + "\u0022" "/> <address addr=" + "\u0022" + ipAddr + "\u0022" + "warning=" + "\u0022" + "No ports found" + "\u0022" "/>" +"</host>")
            return

    data = lines[len(lines)-2]
    temp = list(data)
    temp[len(data)-2] = ""
    data = ''.join(temp)
    lines[len(lines)-2] = data

    with open(masscan_outfile, "w") as jsonfile:
        jsonfile.writelines(lines)

    try:
        f = open(masscan_outfile, "r")
        loaded_json = json.load(f)
    except:
        if attempt:
            return


        print("running masscan again...")
        ip_scan(ipAddr, masscan_interface, attempt=1)
    for x in loaded_json:
        port = x["ports"][0]["port"]
        print(port)
        ip_addr = x["ip"]
        ip_addr = ip_addr.strip()
        #if not hosts[ip_addr]:
        #    hosts[ip_addr] = {}
        try:
            hosts[ip_addr]
        except KeyError:
            hosts[ip_addr] = {}
        #if not hosts[ip_addr][ports]:
        #    hosts[ip_addr][ports] = []
        try:
            hosts[ip_addr][ports]
        except KeyError:
            hosts[ip_addr][ports] = []

        if port not in hosts[ip_addr][ports]:
            hosts[ip_addr][ports].append(port)

    print(hosts)
    with open("scans.txt", 'w') as text_file:
        hcount = 0
        cmds_list = []

        for h, value in hosts.items():
            port_str = "-p"
            print(f"[+] Host: {h}")

            text_file.write(f"{h}")
            hcount+=1
            tstring = h
            tstring += ':-p'
            for p in value["ports"]:
                porto = str(p)
                print(f"    [+] port: {porto}")
                port_str += f"{porto},"
                tstring += f"{porto},"

            tmp_str = port_str[:-1]
            text_file.write(" %s\n" % tmp_str)

            tstring = tstring[:-1]
            cmds_list.append(tstring)

        print("[+] Created %d scan lines in text file: 'scans.txt'" % hcount) 

    nmap_base = "sudo nmap -sS -sV -sC "
    for cmd in cmds_list:
        tmp1 = cmd.split(':')
        host = tmp1[0]
        ports = tmp1[1]

        full_nmap_cmd = nmap_base + host + " " + ports + " -oX " + host + ".xml"

        print(f"[+] Running nmap command: {full_nmap_cmd}")
        os.system(full_nmap_cmd)

def starter(conn, ip):
    NmapXMLInmporter(ip, conn)


def reverse_ip_lookup(conn, ip_address_obj):
    """Funcao reverse_ip_lookup
    Args:
        ip_address_obj (string): ip a analisar
    """

    #source = "reverseIP_"+ip+".xml"

    sql='SELECT `host_id` FROM `host` WHERE `address`=?'
    values = (ip_address_obj,)

    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT MAX(`time`) FROM `ip_time` WHERE host_id=?'

    host_id=host_id[0][0]
    values=(host_id,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]

    reverse_ip = None
    if not ipaddress.ip_address(ip_address_obj).is_private:
        command = f'nslookup {ip_address_obj} 2>/dev/null | grep name | tail -n 1 | cut -d \" \" -f 3'

        if output := os.popen(command).read().strip():
            reverse_ip = output[:-1] if output.endswith(".") else output

        values = (None, host_id, reverse_ip,time)
        sql = 'INSERT INTO `reverse_ip` VALUES (?,?,?,?)'

        conn.execute(sql, values)
    conn.commit()



def blacklistedIP(conn, badip):
    """Funcao que verifica se um IP esta Blacklisted
    Args:
        badip (String): Ip no formato de string
    """

    sql='SELECT `host_id` FROM `host` WHERE `address`=?'
    values = (badip,)
    host_id = conn.execute(sql, values).fetchall()

    sql='SELECT MAX(`time`) FROM `ip_time` WHERE host_id=?'
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
            print(f'{badip} is listed in {bl}' + f' ({answers[0]}: {answer_txt[0]})')

            blist = str(bl)
            sql = 'INSERT INTO `blacklist_ip`(ID, host_id, `Blacklisted`, `time`) VALUES (?,?,?,?)'
            values = (None, host_id, blist, time)
            conn.execute(sql, values)
            conn.commit()

        except dns.resolver.NXDOMAIN:
            print(f'{badip} is not listed in {bl}')

        except dns.resolver.Timeout:
            print(f'WARNING: timeout querying {bl}')

        except dns.resolver.NoNameservers:
            print(f'WARNING: No nameservers for {bl}')

        except dns.resolver.NoAnswer:
            print(f'WARNING: No answer for {bl}')
            
        except UnboundLocalError:
            print("Failed to resolve")
                
        except:
            print("Falha ao obter blacklist")
