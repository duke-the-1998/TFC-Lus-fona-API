#!/usr/bin/env python3

import os
import re
import sqlite3

from core.ips import ip_range_cleaner, ip_scan, starter, validate_ip_address, blacklistedIP,reverse_ip_lookup
from core.dom_checker import blacklisted, db_insert_domain, db_insert_time_domain, is_valid_domain, ssl_version_suported, subdomains_finder, typo_squatting_api
from core.knockpy.knockpy import knockpy


def run_ips(database_fname, fips, iface):
    
    if not fips:
        print("file_name nao definido")
        return None

    ip_aux_file = "cleanIPs.txt"
    if os.path.exists(ip_aux_file):
        os.remove(ip_aux_file)

    for line in fips:
        if validate_ip_address(line):
            ip_range_cleaner(line)
            
    with open (ip_aux_file, "r") as f:
        cf = f.read().splitlines()
        
    os.remove(ip_aux_file)
    conn = sqlite3.connect(database_fname)

    for ip in set(cf):
        if validate_ip_address(ip):
            file = f"{ip}.xml"
            ip_scan(ip, iface)
            starter(conn, file)
            reverse_ip_lookup(conn, ip)
            blacklistedIP(conn, ip)
            if os.path.exists(file):
                os.remove(file)
    print("Ficheiro de ips sem conteudo")

    conn.close()


def is_subdomain(subdomain):
    #subdom =  "/^([a-z]+\:\/{2})?([\w-]+\.[\w-]+\.\w+)$/"
    #subdom = "^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$/"
    #p = re.compile(subdom)
    #return bool(subdomain != None and re.search(p, subdomain))
  
    regex = re.compile('[0-9a-zA-Z\.\-]*\.[0-9a-zA-Z\-]*\.\w+')
    return bool(regex.match(subdomain))

def is_main_domain(domain):
    regex = re.compile('^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
    return bool(regex.match(domain))

def get_main_domain(subdomain):
    #rm.cybers3c.pt
    splited = subdomain.split(".")
    return f"{splited[-2]}.{splited[-1]}"
    

def treat_domains(fdominios):

    fdominios = set(fdominios) #verificar se é necessário
    dominios = []
    subdominios = []

    for fdom in fdominios:
        item = str(fdom).lower()
        if is_main_domain(item): dominios.append(item)
        elif is_subdomain(item): subdominios.append(item)

    treated_fdominios = {}
    #for dom in dominios:
    #    if dom not in treated_fdominios:
    #        treated_fdominios[dom] = []
    treated_fdominios = {dom: [] for dom in dominios if dom not in treated_fdominios}
    

    for sub in subdominios:
        main_domain = get_main_domain(sub)
        if main_domain in treated_fdominios:
            # adicionar à lista o sub
            treated_fdominios[main_domain].append(sub)
        else:
            # deixar o sub como chave
            treated_fdominios[sub] = []

    return treated_fdominios

def run_domains(database_name, fdominios):
            
    if not fdominios or not database_name:
        print("database_name ou Ficheiro de dominios sem conteudo")
    
    conn = sqlite3.connect(database_name)
    
    #domains = {...}
    domains = treat_domains(fdominios)

    print(domains) 
  
    for domain, existent_subdomains in domains.items():  
        #if is_valid_domain(domain):
        #domain = str(domain).lower()
        db_insert_domain(conn, domain)
        db_insert_time_domain(conn, domain)
        ssl_version_suported(conn, domain)
        subdomains_finder(conn, domain, existent_subdomains)
        #subdomains_finder_dnsdumpster(domain)
        #typo_squatting_api(conn, domain)
        #blacklisted(conn, domain)
    
    conn.close()

def delete_aux_files():
    
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    if os.path.exists("scans.txt"):
        os.remove("scans.txt")
    if os.path.exists("mscan.json"):
        os.remove("mscan.json")
    
    print("Todos os ficheiros auxiliares foram apagados!")
        
def clean_useless_files():
      
    if os.path.exists("cleanIPs.txt"):
        os.remove("cleanIPs.txt")
    else:
        print("O ficheiro -> cleanIPs.txt <- não existe!")
        
                