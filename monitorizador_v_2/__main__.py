#!/usr/bin/env python3


#import math
import os
import sys

from deleteSLQ import deleteTabels
from ips import blacklistedIP, ipRangeCleaner, ipScan, starter, validate_ip_address
from dom_checker import blacklisted, create_domains_table, is_valid_domain, ssl_version_suported, create_domain_table_time, subdomains_finder



#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

if __name__=="__main__":

    deleteTabels()
    
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    else:
        print("The file -> cleanIPs.txt <- does not exist!")
    
                       
    fips = open(sys.argv[1], "r").readlines() 
    fdominio = open(sys.argv[2], "r").readlines() 

    if len(fips) != 0:
        for lineIP in fips:
            h=lineIP.strip()
            ipRangeCleaner(h)

        cf = open("cleanIPs.txt", "r").readlines()
        for l in cf:
            ip = l.strip()
            if validate_ip_address(ip):
                f = ip+".xml"
                
                ipScan(ip)
                starter(f)
                blacklistedIP(ip)
                #reverseIpLookup(ip)
                
                os.remove(ip+".xml")
    else:
        print("Ficheiro de ips sem conteudo")
                
    if len(fdominio) != 0: 
        for line in fdominio:  
            domain = line.strip()
            if is_valid_domain(domain):
                create_domains_table(domain)
                create_domain_table_time(domain)
                subdomains_finder(domain)
                ssl_version_suported(domain)
                #funcao para typosquatting
                blacklisted(domain)
    else:
        print("Ficheiro de dominios sem conteudo")

    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    if os.path.exists("scans.txt"):
        os.remove("scans.txt")
    if os.path.exists("mscan.json"):
        os.remove("mscan.json")
    else:
        print("All files deleted!")
    
    #fips.close()
    #fdominio.close()
    