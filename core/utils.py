#!/usr/bin/env python3

import os
import sqlite3

from core.ips import ipRangeCleaner, ipScan, starter, validate_ip_address, blacklistedIP
from core.dom_checker import blacklisted, db_insert_domain, db_insert_time_domain, is_valid_domain, ssl_version_suported, subdomains_finder

#Anteção ah interface do masscan

def run_ips(database_fname, fips, iface):
    
    if not fips:
        print("file_name nao definido")
        return None
    
    ip_aux_file = "cleanIPs.txt"
    if os.path.exists(ip_aux_file):
        os.remove(ip_aux_file)
        
    for line in fips:
        ipRangeCleaner(line)
    
    with open (ip_aux_file, "r") as f:
        cf = f.read().splitlines()

    os.remove(ip_aux_file)
    conn = sqlite3.connect(database_fname)

    for ip in cf:
        if validate_ip_address(ip):
            f = ip + ".xml"
            ipScan(ip, iface)
            starter(conn, f)
            blacklistedIP(conn, ip)
            #reverseIpLookup(conn, ip)
            os.remove(ip+".xml")
    else:
        print("Ficheiro de ips sem conteudo")
    
    conn.close()

def run_domains(database_name, fdominios):
            
    if not fdominios or not database_name:
        print("database_name ou Ficheiro de dominios sem conteudo")
    
    conn = sqlite3.connect(database_name)

    for domain in fdominios:  
        if is_valid_domain(domain):
            db_insert_domain(conn, domain)
            db_insert_time_domain(conn, domain)
            ssl_version_suported(conn, domain)
            subdomains_finder(conn, domain)
            #subdomains_finder_dnsdumpster(domain)
            #funcao para typosquatting
            blacklisted(conn, domain)
    
    conn.close()

def delete_aux_files():
    
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    if os.path.exists("scans.txt"):
        os.remove("scans.txt")
    if os.path.exists("mscan.json"):
        os.remove("mscan.json")
    
    print("All files deleted!")
        
def clean_useless_files():
      
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    else:
        print("The file -> cleanIPs.txt <- does not exist!")