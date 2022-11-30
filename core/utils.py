#!/usr/bin/env python3

import os
import sqlite3

from core.ips import ipRangeCleaner, ipScan, starter, validate_ip_address, blacklistedIP
from core.dom_checker import blacklisted, db_insert_domain, db_insert_time_domain, is_valid_domain, ssl_version_suported, subdomains_finder

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
        

def run_domains(database_name, fdominios):
            
    if not fdominios or not database_name:
        print("database_name ou Ficheiro de dominios sem conteudo")
    
    conn = sqlite3.connect(database_name)

    for domain in fdominios:  
        if is_valid_domain(domain):
            db_insert_domain(conn, domain)
            db_insert_time_domain(conn, domain)
            ssl_version_suported(conn, domain)
            subdomains_finder(domain)
            #subdomains_finder_dnsdumpster(domain)
            #funcao para typosquatting
            blacklisted(domain)
    
    conn.close()

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