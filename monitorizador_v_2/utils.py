#!/usr/bin/env python3

import os

from ips import ipRangeCleaner, ipScan, starter, validate_ip_address, blacklistedIP
from dom_checker import blacklisted, create_domains_table, is_valid_domain, ssl_version_suported, create_domain_table_time,subdomains_finder_dnsdumpster

#Anteção ah interface do masscan
masscan_interface = "enp0s3"

def run_ips(fips):
    
    if len(fips) != 0:
        for lineIP in fips:
            h=lineIP.strip()
            ipRangeCleaner(h)

            cf = open("cleanIPs.txt", "r").readlines()
            for l in cf:
                ip = l.strip()
                if validate_ip_address(ip):
                    f = ip+".xml"
                    ipScan(ip, masscan_interface)
                    starter(f)
                    blacklistedIP(ip)
                    #reverseIpLookup(ip)
                    os.remove(ip+".xml")
    else:
        print("Ficheiro de ips sem conteudo")
        

def run_domains(fdominio):
            
    if len(fdominio) != 0: 
        for line in fdominio:  
            domain = line.strip()
            #if is_valid_domain(domain): utiliza crt.sh.... mudar!!!
            create_domains_table(domain)
            create_domain_table_time(domain)
            ssl_version_suported(domain)
            #subdomains_finder(domain)
            subdomains_finder_dnsdumpster(domain)
            #funcao para typosquatting
            blacklisted(domain)
    else:
        print("Ficheiro de dominios sem conteudo")
        
def delete_aux_files():
    
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    if os.path.exists("scans.txt"):
        os.remove("scans.txt")
    if os.path.exists("mscan.json"):
        os.remove("mscan.json")
    else:
        print("All files deleted!")
        
def clean_useless_files():
      
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    else:
        print("The file -> cleanIPs.txt <- does not exist!")