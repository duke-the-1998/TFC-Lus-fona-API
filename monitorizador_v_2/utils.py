#!/usr/bin/env python3

import os
import sys

from ips import blacklistedIP, ipRangeCleaner, ipScan, starter, validate_ip_address
from dom_checker import blacklisted, create_domains_table, is_valid_domain, ssl_version_suported, create_domain_table_time, subdomains_finder


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
                    # ipScan(ip, masscan_interface)
                    #  starter(f)
                    #  blacklistedIP(ip)
                    #reverseIpLookup(ip)
                    os.remove(ip+".xml")
    else:
        print("Ficheiro de ips sem conteudo")
        

def run_domains(fdominio):
            
    if len(fdominio) != 0: 
        for line in fdominio:  
            domain = line.strip()
            if is_valid_domain(domain):
                create_domains_table(domain)
                create_domain_table_time(domain)
                ssl_version_suported(domain)
                subdomains_finder(domain)
                #ssl_version_suported(domain)
                #funcao para typosquatting
                blacklisted(domain)
            
            #subenum(domain, no_ip=False)       
            
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