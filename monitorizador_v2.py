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

    #Atencao ah interface
    command = "masscan " + ipAddr + " --rate=1500 -p0-65535 -e tun0 -oJ mscan.json"

    print("[+] Running the masscan enumeration:  %s" % command)
    os.system(command)

    f = open("mscan.json", "r")
    lines = f.readlines()
    f.close()
    if len(lines) == 0:
        simplefile = open(ip + ".xml","w+")
        simplefile.write("<host><status state=" + u"\u0022" + "down" + u"\u0022" "/> <address addr=" + u"\u0022" + ip + u"\u0022" + "warning=" + u"\u0022" + "No ports found" + u"\u0022" "/>" +"</host>")  
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

            if port in hosts[ip_addr][ports]:
                pass
            else:
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
      
        text_file.close()

        nmap_base = "sudo nmap -sS -sV -sC "
        for cmd in cmds_list:
            tmp1 = cmd.split(':')
            host = tmp1[0]
            ports = tmp1[1]
        
            full_nmap_cmd = nmap_base + host + " " + ports + " " + "-oX " + host + ".xml"
            
            print("[+] Running nmap command: %s" % full_nmap_cmd)
            os.system(full_nmap_cmd)


def reverseIpLookup(ip_address_obj):
    
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
               
                print(msg)
    else:
        msg = "Private IP"

    f = open("reverseIP_"+ip+".xml", "a")
    f.write("<reverseip reverseIp=" + u"\u0022" + msg + u"\u0022" + "/>"+"\n")
    f.close()


#bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net"]

def blacklisted(badip):
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

    for bl in bls:
        try:
            f = open("blacklist_"+ip+".xml", "a")
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print((badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))

            f.write("<blacklistinfo blacklisted=" + u"\u0022" + bl + u"\u0022" + "/>"+"\n")
            f.close()
            
        except dns.resolver.NXDOMAIN:
            print(badip + ' is not listed in ' + bl)
                
        except dns.resolver.Timeout:
            print('WARNING: Timeout querying ' + bl)
            #f = open("blacklist_"+ip+".xml", "a")
            #f.write("<blacklistinfo warning=" + u"\u0022" + "Timeout querying " + bl + u"\u0022" + "/>"+"\n")
            #f.close()
                        
        except dns.resolver.NoNameservers:
            print('WARNING: No nameservers for ' + bl)
            #f = open("blacklist_"+ip+".xml", "w")
            #f.write("<blacklistinfo warning=" + u"\u0022" + "No nameservers for " + bl + u"\u0022" + "/>"+"\n")
            #f.close()
                
        except dns.resolver.NoAnswer:
            print('WARNING: No answer for ' + bl)
            #f = open("blacklist_"+ip+".xml", "w")
            #f.write("<blacklistinfo warning=" + u"\u0022" + "No answer for " + bl + u"\u0022" + "/>"+"\n")
            #f.close()
            
def ipRangeCleaner(ip):
   
    f = open("cleanIPs.txt", "a") 
    txt = "\n".join([str(x) for x in ipaddress.ip_network(ip).hosts()])+"\n"
    f.write(txt) 
    f.close() 

if __name__=="__main__":
    fl = open(sys.argv[1], "r").readlines() 
    
    for line in fl:
        h=line.strip()
        ipRangeCleaner(h)
        
        cf = open("cleanIPs.txt", "r").readlines()
        for l in cf: 
            ip = l.strip()
            if validate_ip_address(ip):
                ipScan(ip)
                reverseIpLookup(ip)
                blacklisted(ip)  
    
               