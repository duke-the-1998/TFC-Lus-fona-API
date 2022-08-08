#!/usr/bin/env python3

import nmap
import sys
import ipaddress
import requests
import argparse
import re
import subprocess
import socket
#----------------

import os
import urllib.request
import urllib.request, urllib.error, urllib.parse
import dns.resolver
from urllib.request import urlopen
#----auxiliares-----

def validate_ip_address(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def ipScan():
    #funcao que le um ficheiro de ip, verifica se sao validos e em caso de o ip ser valido
    #faz scan a esse ip
    nm = nmap.PortScanner()
    file = open(sys.argv[1], "r")

    while True:
       
        l = file.readlines()
        if not l:
            return "erro"
       
        for line in l:
            ip = line.strip()
            #resolver problema do strict (defaul ou igual a true nao funciona) 
            ip_address_obj = ipaddress.ip_network(ip, strict=False)
            print(nm.scan(line, arguments='-sS'))





def reverseIpLookup():
    #primeiro verificar se Ip é publico

    file = open(sys.argv[1], "r")

    while True:
       
        l = file.readlines()
        if not l:
            return None
       
        for line in l:
            ip = line.strip().split("/", 1)

            if validate_ip_address(ip[0]) == True:
                ip_address_obj = ip[0]
                        
                types = ["AAAA", "MX", "CNAME"]

                for t in types:
                    command = "nslookup -type=" + t + " " + ip_address_obj
                    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
                    output, error = process.communicate()
                    print(t)
                    if(error):
                        print(error)
                    print(output.decode("utf=8"))
            else:
                pass
                
                   

    #1. obter ip
    #2. reverser Ip
    #3. percorrer a lista de blacklists
    #4. dns lookup
    #5. obter resultado

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)


def content_test(url, badip):
    """
    Check to see if it is an BadIP
        Args:
            url -- the URL to request data from
            badip -- the IP address in question
        Returns:
            Boolean
    """

    try:
        request = urllib.request.Request(url)
        opened_request = urllib.request.build_opener().open(request)
        html_content = opened_request.read()
        retcode = opened_request.code
        retcode == 200
        matches = retcode 
        matches = matches and re.findall(badip, html_content)

        return len(matches) == 0
    except (Exception) :
        return False

bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
       "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
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

URLS = [
    #TOR
    ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    #AlienVault
    ('http://reputation.alienvault.com/reputation.data',
     'is not listed on AlienVault',
     'is listed on AlienVault',
     True),

    #BlocklistDE
    ('http://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True),

    #Dragon Research Group - SSH
    ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'is not listed on Dragon Research Group - SSH',
     'is listed on Dragon Research Group - SSH',
     True),

    #Dragon Research Group - VNC
    ('http://dragonresearchgroup.org/insight/vncprobe.txt',
     'is not listed on Dragon Research Group - VNC',
     'is listed on Dragon Research Group - VNC',
     True),

    #OpenBLock
    ('http://www.openbl.org/lists/date_all.txt',
     'is not listed on OpenBlock',
     'is listed on OpenBlock',
     True),

    #NoThinkMalware
    ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'is not listed on NoThink Malware',
     'is listed on NoThink Malware',
     True),

    #NoThinkSSH
    ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True),

    #Feodo
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on Feodo',
     'is listed on Feodo',
     True),

    #antispam.imp.ch
    ('http://antispam.imp.ch/spamlist',
     'is not listed on antispam.imp.ch',
     'is listed on antispam.imp.ch',
     True),

    #dshield
    ('http://www.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True),

    #malc0de
    ('http://malc0de.com/bl/IP_Blacklist.txt',
     'is not listed on malc0de',
     'is listed on malc0de',
     True),

    #MalWareBytes
    ('http://hosts-file.net/rss.asp',
     'is not listed on MalWareBytes',
     'is listed on MalWareBytes',
     True)]

#    #Spamhaus DROP (in CIDR format, needs parsing)
#    ('https://www.spamhaus.org/drop/drop.txt',
#     'is not listed on Spamhaus DROP',
#     'is listed on Spamhaus DROP',
#     False),
#    #Spamhaus EDROP (in CIDR format, needs parsing)
#    ('https://www.spamhaus.org/drop/edrop.txt',
#     'is not listed on Spamhaus EDROP',
#     'is listed on Spamhaus EDROP',
#     False)]

def blacklisted():

    file = open(sys.argv[1], "r")

    while True:
       
        l = file.readlines()
        if not l:
            return None
       
        for line in l:
            ip = line.strip().split("/", 1)

            if validate_ip_address(ip[0]) == True:
                badip = ip[0]

                #IP Geo Lookup
                reversed_dns = socket.getfqdn(badip)
                geoip = urllib.request.urlopen('http://api.hackertarget.com/geoip/?q='
                                        + badip).read().rstrip()

                print((green('\nThe FQDN for {0} is {1}\n'.format(badip, reversed_dns))))
                print((red('Geo Information:')))
                print((green(geoip)))
                print('\n')

                BAD = 0
                GOOD = 0

                for url, succ, fail, mal in URLS:
                    if content_test(url, badip) and args.success:
                        #print(green('{0} {1}'.format(badip, succ)))
                        GOOD += 1
                    else:
                        #print(red('{0} {1}'.format(badip, fail)))
                        BAD += 1
                    
                            
                BAD = BAD
                GOOD = GOOD

                for bl in bls:
                        try:
                            my_resolver = dns.resolver.Resolver()
                            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
                            my_resolver.timeout = 5
                            my_resolver.lifetime = 5
                            answers = my_resolver.query(query, "A")
                            answer_txt = my_resolver.query(query, "TXT")
                            print((red(badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0])))
                            BAD = BAD + 1

                        except dns.resolver.NXDOMAIN:
                            print((green(badip + ' is not listed in ' + bl)))
                            GOOD = GOOD + 1

                        except dns.resolver.Timeout:
                            print((blink('WARNING: Timeout querying ' + bl)))

                        except dns.resolver.NoNameservers:
                            print((blink('WARNING: No nameservers for ' + bl)))

                        except dns.resolver.NoAnswer:
                            print((blink('WARNING: No answer for ' + bl)))
                            #  print(red('\n{0} is on {1}/{2} blacklists.\n'.format(badip, BAD, (GOOD+BAD))))





if __name__=="__main__":
    blacklisted()

