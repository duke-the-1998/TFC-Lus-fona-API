#!/usr/bin/env python3

import os
import re
import sqlite3
import copy
from core.ips import ip_range_cleaner, ip_scan, starter, validate_ip_address, blacklistedIP, reverse_ip_lookup, get_dicIp
from core.dom_checker import blacklisted, db_insert_domain, ssl_version_suported, subdomains_finder, typo_squatting_api, \
    get_dicDominio

from core.knockpy.knockpy import knockpy

jsonDominios = {"dominios": []}

jsonIps = {"ips": []}


def run_ips(fips, iface):


    ip_aux_file = "cleanIPs.txt"

    if os.path.exists(ip_aux_file):
        os.remove(ip_aux_file)


    if validate_ip_address(fips):
        ip_range_cleaner(fips)

    with open(ip_aux_file, "r") as f:
        cf = f.read().splitlines()

    os.remove(ip_aux_file)

    for ip in set(cf):
        if validate_ip_address(ip):
            file = f"{ip}.xml"
            ip_scan(ip, iface)
            starter(file)
            reverse_ip_lookup(ip)
            blacklistedIP(ip)
            dic1 = get_dicIp()
            jsonIps['ips'].append(copy.deepcopy(dic1))
            if os.path.exists(file):
                os.remove(file)
    print("Ficheiro de ips sem conteudo")


def run_domains(dominio):
    domain = treat_domains(dominio)

    db_insert_domain(domain)
    ssl_version_suported(domain)
    subdomains_finder(domain)
    typo_squatting_api(domain)
    blacklisted(domain)
    dic1 = get_dicDominio()
    jsonDominios['dominios'].append(copy.deepcopy(dic1))


def is_subdomain(subdomain):
    regex = re.compile('[0-9a-zA-Z.\-]*\.[0-9a-zA-Z\-]*\.\w+')
    return bool(regex.match(subdomain))


def is_main_domain(domain):
    regex = re.compile('^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
    return bool(regex.match(domain))


def get_main_domain(subdomain):
    splited = subdomain.split(".")
    return f"{splited[-2]}.{splited[-1]}"


def treat_domains(fdom):
    global treated_dominio

    item = str(fdom).lower()
    if is_main_domain(item):
        treated_dominio = fdom
    elif is_subdomain(item):
        main_domain = get_main_domain(item)
        treated_dominio = main_domain

    return treated_dominio



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
