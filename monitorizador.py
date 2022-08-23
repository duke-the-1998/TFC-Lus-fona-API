#!/usr/bin/env python3

import os
#import nmap
import sys
import ipaddress
import requests
import argparse
#import re
import subprocess
import socket
import urllib.request
import urllib.request, urllib.error, urllib.parse
import dns.resolver
import json
from urllib.request import urlopen
#import xmltodict
#import masscan

#----auxiliares-----
def validate_ip_address(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def validate_network(addr):
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except ValueError:
        return False

def isPrivate(ip):
    try:
        ipaddress.ip_address(ip).is_private
        return True
    except ValueError:
        return False


def ipScan(ipAddr):
    hosts = {}
    ports = "ports"
    #print(ipAddr)
    #command = 'masscan ' + '-p1-65535 --rate 100000 -oJ ' + 'scan.json ' + ipAddr

    #command = "masscan 10.0.0.205 --rate=1500 -p0-65535 -e tun0 -oJ mscan.json"
    command = "masscan " + ipAddr + "--rate=1500 -p0-65535 -e tun0 -oJ mscan.json"

    #command = "masscan 127.0.0.1 --rate 1000 -p1-65535 -oJ mscan.xml"
    print("[+] Running the masscan enumeration:  %s" % command)
    os.system(command)

    f = open("mscan.json", "r")
    
    lines = f.readlines()
    f.close()
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
            ### Add the IP address to dictionary if it doesn't already exist
        try:
            hosts[ip_addr]
        except KeyError:
            hosts[ip_addr] = {}

        ### Add the port list to dictionary if it doesn't already exist
        try:
            hosts[ip_addr][ports]
        except KeyError:
            hosts[ip_addr][ports] = []

        ## append the port to the list
        if port in hosts[ip_addr][ports]:
            pass
        else:
            hosts[ip_addr][ports].append(port)


    # Create host and port scan text file
    text_file = open("scans.txt", 'w')

    hcount = 0
    cmds_list = []

    for h in hosts:
        port_str = "-p"
        print("[+] Host: %s" % h)
        # Write the host
        text_file.write("%s" % h)
        hcount+=1
        tstring = h
        tstring += str(':-p')
        for p in hosts[h]["ports"]:
            blah = str(p)
            print("    [+] Port: %s" % blah)
            port_str += blah 
            port_str += str(",")
            tstring += blah 
            tstring += str(",")
        tmp_str = port_str[:-1]
        text_file.write(" %s\n" % tmp_str)

        tstring = tstring[:-1]
        cmds_list.append(tstring)
    print("[+] Created %d scan lines in text file: 'scans.txt'" % hcount)
    ## save this file just for inspection
    text_file.close()

    ### Loop through and run nmap command, running each scan against a single host with precise ports, and saving the file with IP address (i.e., <IP>.txt)
    # Declare the nmap base command
    nmap_base = "sudo nmap -A -Pn "
    for cmd in cmds_list:
    #print("cmd: %s" % cmd)
        tmp1 = cmd.split(':')
        host = tmp1[0]
        ports = tmp1[1]
        #print("ports: %s" % ports)
        full_nmap_cmd = nmap_base + host + " " + ports + " " + "-oN " + host + ".txt"
        print("[+] Running nmap command: %s" % full_nmap_cmd)
        os.system(full_nmap_cmd)



def reverseIpLookup(ip_address_obj):
    #primeiro verificar se Ip é publico
    #if isPrivate(ip_address_obj) == False:
    types = ["AAAA", "MX", "CNAME"]

    for t in types:
        command = "nslookup -type=" + t + " " + ip_address_obj
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        print(t)
        if(error):
            print(error)
        print(output.decode("utf=8"))
    #else:
       # print("Private IP")
            


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

def blacklisted(badip):

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
            print((badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))
            BAD = BAD + 1
    
        except dns.resolver.NXDOMAIN:
            #print((badip + ' is not listed in ' + bl))
            GOOD = GOOD + 1
        
        except dns.resolver.Timeout:
            print(('WARNING: Timeout querying ' + bl))

        except dns.resolver.NoNameservers:
            print(('WARNING: No nameservers for ' + bl))

        except dns.resolver.NoAnswer:
            print(('WARNING: No answer for ' + bl))


if __name__=="__main__":
    file = open(sys.argv[1], "r").readlines() 
    ipScan()
    for line in file:
     
        ip = line.strip().split("/", 1)
        ipToScan = line.strip()
        
        if validate_ip_address(ip[0]): # or validate_network(ipScan(ip)):  
            ipScan(ip(0))
            reverseIpLookup(ip[0])
            blacklisted(ip[0])
        