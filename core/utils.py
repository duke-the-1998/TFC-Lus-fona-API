#!/usr/bin/env python3

import os
import re
import copy
from core.ips import ip_range_cleaner, ip_scan, starter, validate_ip_address, blacklistedIP, reverse_ip_lookup, \
    get_dicIp
from core.dom_checker import blacklisted, db_insert_domain, ssl_version_suported, subdomains_finder, typo_squatting_api, \
    get_dicDominio

# Dicionário para armazenar informações sobre os domínios
jsonDominios = {"dominios": []}

# Dicionário para armazenar informações sobre os IPs
jsonIps = {"ips": []}


def run_ips(fips, iface):
    """
        Função para realizar várias operações relacionadas a IPs.

        Parâmetros:
            fips (str): O IP a ser processado
            iface (str): Interface de rede a ser usada
        """

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
    """
        Função para realizar várias operações relacionadas a domínios.

        Parâmetros:
            dominio (str): O domíno a ser processado
        """

    domain = treat_domains(dominio)
    db_insert_domain(domain)
    ssl_version_suported(domain)
    subdomains_finder(domain)
    typo_squatting_api(domain)
    blacklisted(domain)
    dic1 = get_dicDominio()
    jsonDominios['dominios'].append(copy.deepcopy(dic1))


def is_subdomain(subdomain):
    """
        Verifica se é um subdomínio válido.

        Parâmetros:
            subdomain (str): O subdomínio a ser verificado

        Retorna:
            True se for um subdomíno válido e false caso contrário

        """
    regex = re.compile('[0-9a-zA-Z.\-]*\.[0-9a-zA-Z\-]*\.\w+')
    return bool(regex.match(subdomain))


def is_main_domain(domain):
    """
        Verifica se é um domínio principal válido.

        Parâmetros:
            O domínio a ser verificado

        Retorna:
            True se for um domínio principal válido, False caso contrário
        """
    regex = re.compile('^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
    return bool(regex.match(domain))


def get_main_domain(subdomain):
    """
        Obtém o domínio principal a partir de um subdomínio.

        Parâmetros:
            subdomain (str): O subdomínoo do qual o domínio principal será extraido

        Retorna:
            O domínio principal correspondente
        """
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
