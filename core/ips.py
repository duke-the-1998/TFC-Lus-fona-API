#!/usr/bin/env python3
import datetime
import ipaddress
import logging
import logging.config
import os
import subprocess
import dns.resolver
from bs4 import BeautifulSoup
from core.ip_models import ModelHost, ModelPort

#cabeçalho com variaveis globais
#interface masscan pode ser mudada
#masscan_interface = "enp0s3"
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
jsonIp = {}
#nome dos ficheiros


def get_dicIp():
    return jsonIp

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
    def __init__(self, source):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.source = source
        self.hosts = []
        self.__process__()

    def __process__(self):
        self.logger.error("Not implemented here...")
        raise NotImplementedError("import")

    def __store__(self):

        jsonIp["hosts"] = []
        dt = datetime.datetime.now()
        for host in self.hosts:

            host1 = {
                "address": host.address,
                "name": host.name,
                "port": [{
                    "date": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "portNumber": port.nr,
                    "protocol": port.proto,
                    "description": port.state,
                    "state": port.state,
                    "ssl": port.ssl
                }for port in host.ports]
            }


            jsonIp["hosts"].append(host1)


        

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

    # run masscan
    masscan_cmd = (f"sudo masscan {ipAddr} --rate=400 -p0-65535 -e {masscan_interface} > masscan.txt")
    subprocess.check_call(masscan_cmd, shell=True)

    # grep and filter ports from Masscan output and feed into Nmap scan
    grep_cmd = ("awk '{print $4}' masscan.txt | cut -d '/' -f 1 | awk -F/ '{print$1}' ORS=',' ")
    grepped_ports = subprocess.run(grep_cmd, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    ports = grepped_ports.stdout

    if not ports:
        with open(f"{ipAddr}.xml", "w+") as simplefile:
            simplefile.write("<host><status state=" + "\u0022" + "down" + "\u0022" "/> <address addr=" + "\u0022" + ipAddr + "\u0022" + "warning=" + "\u0022" + "No ports found" + "\u0022" "/>" +"</host>")
            return
        
    #Nmap scan, and output results to a txt file
    nmap_cmd = (f"sudo nmap -sS -sV -p {ports} {ipAddr} -oX {ipAddr}.xml")
    print(f"[+] Running nmap command: {nmap_cmd}")
    subprocess.check_call(nmap_cmd, shell=True)

    #delete masscan.txt
    subprocess.run(['rm masscan.txt'], shell=True)
    


def starter(ip):
    NmapXMLInmporter(ip)


def reverse_ip_lookup(ip_address_obj):
    """Funcao reverse_ip_lookup
    Args:
        ip_address_obj (string): ip a analisar
    """

    reverse_ip = None
    if not ipaddress.ip_address(ip_address_obj).is_private:
        command = f'nslookup {ip_address_obj} 2>/dev/null | grep name | tail -n 1 | cut -d \" \" -f 3'

        if output := os.popen(command).read().strip():
            reverse_ip = output[:-1] if output.endswith(".") else output

        dt = datetime.datetime.now()
        jsonIp["revrse_ip_lookup"] = {
           "reverse_ip": reverse_ip,
            "time": dt.strftime("%Y-%m-%d %H:%M:%S")
        }




def blacklistedIP( badip):
    """Funcao que verifica se um IP esta Blacklisted
    Args:
        badip (String): Ip no formato de string
    """

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

    jsonIp["blacklist_ips"]: []
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

            dt = datetime.datetime.now()
            blacklist = {
                "blacklist": blist,
                "time": dt.strftime("%Y-%m-%d %H:%M:%S")
            }

            jsonIp["blacklist_ips"].append(blacklist)


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
