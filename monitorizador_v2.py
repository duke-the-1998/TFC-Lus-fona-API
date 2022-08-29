#!/usr/bin/env python3

import os
import sys
import ipaddress
import requests
import argparse
import subprocess
import socket
import urllib.request
import urllib.request, urllib.error, urllib.parse
import dns.resolver
import json
from urllib.request import urlopen
import xmltodict
#import pprint


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
    ipaddress.ip_address(ip).is_private
        

#---------------------------------------------------------

def ipScan(ipAddr):
    hosts = {}
    ports = "ports"
      
    #print(ipAddr)
    #command = 'masscan ' + '-p1-65535 --rate 100000 -oJ ' + 'scan.json ' + ipAddr

    #command = "masscan 10.0.0.205 --rate=1500 -p0-65535 -e tun0 -oJ mscan.json"
    command = "masscan " + ipAddr + " --rate=1500 -p0-65535 -e tun0 -oJ mscan.json"

    #command = "masscan 127.0.0.1 --rate 1000 -p1-65535 -oJ mscan.xml"
    print("[+] Running the masscan enumeration:  %s" % command)
    os.system(command)

    f = open("mscan.json", "r")
    
    lines = f.readlines()
    f.close()
    if len(lines) == 0:
        simplefile = open("nmap_"+ ip + ".xml","w+")
        simplefile.write("<nmaprun warning=" + u"\u0022" + "No ports found" + u"\u0022" + "/>")
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
        ######apagar print!!!!
        print("[+] Created %d scan lines in text file: 'scans.txt'" % hcount) 
        ## save this file just for inspection
        text_file.close()

        ### Loop through and run nmap command, running each scan against a single host with precise ports, and saving the file with IP address (i.e., <IP>.txt)
        # Declare the nmap base command
        nmap_base = "sudo nmap -sS -sV -sC "
        for cmd in cmds_list:
        #print("cmd: %s" % cmd)
            tmp1 = cmd.split(':')
            host = tmp1[0]
            ports = tmp1[1]
            #print("ports: %s" % ports)
            full_nmap_cmd = nmap_base + host + " " + ports + " " + "-oX " + host + ".xml"
            
            ######apagar print!!!!
            print("[+] Running nmap command: %s" % full_nmap_cmd)
            os.system(full_nmap_cmd)


def reverseIpLookup(ip_address_obj):
    
    if isPrivate(ip_address_obj) == False:
        types = ["AAAA", "MX", "CNAME"]

        for t in types:
            command = "nslookup -type=" + t + " " + ip_address_obj
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
      
            if(error):
                f = open("reverseIP_"+ip+".xml", "w")
                f.write("<reverseip reverseIp=" + u"\u0022" + "error" + u"\u0022" + "/>")
                f.close()
            else:
                f = open("reverseIP"+ip+".xml", "w")
                f.write("<reverseip reverseIp=" + u"\u0022" + output.decode("utf=8") + u"\u0022" + "/>")
                f.close()
          
    else:
        f = open("reverseIP_"+ip+".xml", "w")
        f.write("<reverseip reverseIp=" + u"\u0022" + "Private IP" + u"\u0022" + "/>")
        f.close()


'''
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
'''
bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net"]

def blacklisted(badip):

    '''
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
'''
    bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net"]

   
    for bl in bls:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print((badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))

            f = open("blacklist_"+ip+".xml", "a")
            f.write("<blacklistinfo blacklisted=" + u"\u0022" + bl + u"\u0022" + "/>"+"\n")
            f.close()
            
        except dns.resolver.NXDOMAIN:
                print(badip + ' is not listed in ' + bl)
                
        except dns.resolver.Timeout:
                print('WARNING: Timeout querying ' + bl)
                f = open("blacklist_"+ip+".xml", "a")
                f.write("<blacklistinfo warning=" + u"\u0022" + "Timeout querying " + bl + u"\u0022" + "/>"+"\n")
                f.close()
                        
        except dns.resolver.NoNameservers:
                print('WARNING: No nameservers for ' + bl)
                f = open("blacklist_"+ip+".xml", "w")
                f.write("<blacklistinfo warning=" + u"\u0022" + "No nameservers for " + bl + u"\u0022" + "/>"+"\n")
                f.close()
                
        except dns.resolver.NoAnswer:
                print('WARNING: No answer for ' + bl)
                f = open("blacklist_"+ip+".xml", "w")
                f.write("<blacklistinfo warning=" + u"\u0022" + "No answer for " + bl + u"\u0022" + "/>"+"\n")
                f.close()
            

    
if __name__=="__main__":
    file = open(sys.argv[1], "r").readlines() 
    
    for line in file:
     
       # ipGama = line.strip().split("/", 1)
        ip = line.strip()
       # perguntar se a rede tambem vai para a blacklist e reverse IP???!!!!! caso contrario mudar if 
       
        if validate_ip_address(ip): # or validate_network(ip): 
            if not os.path.exists(ip):
                os.makedirs(ip)
    
        ipScan(ip)
        reverseIpLookup(ip)
        blacklisted(ip)
       