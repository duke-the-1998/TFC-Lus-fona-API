#!/usr/bin/env python3

import datetime
import re
import socket
import ssl
import sys
import time
import dns.resolver
import requests

from core.crtsh.crtsh import crtshAPI
from urllib.parse import urlparse
from core.crtsh.crtsh_cert_info import check_cert
from core.knockpy.knockpy import knockpy
from core.security_headers import *
from prettytable import PrettyTable

def is_valid_domain(dominio):
    """Funcao auxiliar que recebe uma string e verifica se eh 
    um dominio valido

    Args:
        dominio (String): dominio no formato de string lido do 
        ficheiro dominios.txt

    Returns:
        Boolean: Retorna True se o dominio != None e se cumprir
        os requisitos da regex
    """
 
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"

    p = re.compile(regex)

    return bool(dominio != None and re.search(p, dominio))

#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip().lower()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + "\n")


def simplify_list(lista):
    """ list of list to list, removing duplicates
    """
    try:
        flat_list = [item for sublist in lista for item in sublist]
        return list(set(flat_list))
    except Exception:
        print("Erro ao fazer flatten da lista de subdominios")

def get_crtsh_subdomains(target):
    req_json = None

    for _ in range(3):
        req_json = crtshAPI().search(target)
        if req_json: break
        time.sleep(1)
    
    if not req_json:
        print(f"Pesquisa ao crt.sh falhou para {target}")
                    
    subdomains = [str(value['name_value']).split("\n") for value in req_json]
    return simplify_list(subdomains)

def get_all_subdomains(target, existent_subdomains):
    """ Obtem subdominios do input, crt.sh e hackertarget
    """
    subdomains_knockpy = knockpy(target)
    subdomains_crtsh = get_crtsh_subdomains(target)
    subdomains_hackertarget = subdomains_finder_dnsdumpster(target)
    
    all_subdomains_notclean = list(set(subdomains_crtsh + subdomains_knockpy + 
                                existent_subdomains ))#TODO adicionar hackertarget, falta chave da api + subdomains_hackertarget
    all_subdomains_unique = list(filter(lambda s: not s.startswith('*'), all_subdomains_notclean))

    return list(filter(lambda s: is_valid_domain(s), all_subdomains_unique))

def check_reason(reason):

    if "[SSL: CERTIFICATE_VERIFY_FAILED]" in reason:
        return "Falha ao verificar certificado SSL"

    elif "[Errno -5]" in reason:
        return "Nenhum endereço associado ao hostname"

    elif "[Errno 111]" in reason:
        return "Conexão recusada"

    elif "[Errno 101]" in reason: 
        return "Rede inacessível"

    elif "[Errno -3]" in reason: 
        return "Falha temporaria na resolução de nomes"

    elif "[Errno -2]" in reason: 
        return "Nome ou serviço desconhecido"

    elif "[Errno 113]" in reason: 
        return "Falha a estabelecer ligação"  

    elif "[Errno 104]" in reason: 
        return "Conexão restabelecida pelo par"
    
    #EOF occurred in violation of protocol (_ssl.c:1131)
    elif "EOF" in reason: 
        return "SSL error"  

    else:
        return reason


def subdomains_finder(conn, domains, existent_subdomains): 
    try:
        if not conn or not domains:
            print("argumento em falta")

        target = clear_url(domains)
          
        all_subdomains = get_all_subdomains(target, existent_subdomains)

        for subdomain in all_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
            except Exception:
                ip = None

            result_dict = check_cert(subdomain)
            start_date = result_dict.get('start_date')
            valid_until = result_dict.get('valid_until')
            org_name = result_dict.get('org_name')
            reason = str(result_dict.get('reason'))
            
            days_left = check_reason(reason)

            print(
                f"\n[+] domain: {subdomain}, ip: {ip}, start_date: {start_date}, valid_until: {valid_until}, days_left: {days_left}, org_name: {org_name} [+]\n"
            )

            sql = 'SELECT id FROM domains WHERE domains=?'
            values = (domains,)
            domID = conn.execute(sql, values).fetchall()
            domID = domID[0][0]

            sql='SELECT MAX(`Time`) FROM `domain_time` WHERE domain_id=?'
            values=(domID,)
            time = conn.execute(sql, values).fetchall()
            time = time[0][0]

            sql = 'INSERT INTO `subdomains`(id, domain_id, subdomain, ip, start_date, valid_until, days_left, org_name, Time) VALUES (?,?,?,?,?,?,?,?,?)'
            values = (None, domID, subdomain, ip, start_date, valid_until, days_left, org_name, time )
            conn.execute(sql, values)

            conn.commit()

            print(f"[+] Cabecalhos de Seguranca: {subdomain} [+]\n")

            check_sec_headers(conn, subdomain, domains)
    except Exception:
        print("Falha a obter subdominios")
    
def subdomains_finder_dnsdumpster(domain):
    """NOVA FUNCAO PARA PROCURAR SUBDOMINIOS
    Usa a api hackertarget (dnsdumpster)
    retorna subdominios encontrados
    """
    try:
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        lines = api.text.split("\n")
        if '' in lines:
            lines.remove('')
            
        #subdominio,ip
        return [line.split(',')[0] for line in lines if "," in line]  

    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
    except Exception:
        print(f"hackertarget nao encontrou subdominios para: {domain}")
        return []
    
#---------Webcheck------------
#----------https--------------
def ssl_version_suported(conn, hostname):
    """Funcao que verica que versoes SSL/TLS estao a ser usadas"""
    if not conn or not hostname:
        print("argumento em falta")

    print(f"\n[!] ---- TARGET: {hostname} ---- [!] \n")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
            if ssock.version():
                check_ssl_versions(hostname, ssock, conn)
            else:
                print("Certificado nao encontrado")
    except Exception:
        print(f"Dominio nao alcancavel: {hostname}")


def check_ssl_versions(hostname, ssock, conn):
    
    in_use = ssock.version()
    SSLv2 = str(ssl.HAS_SSLv2)
    SSLv3 = str(ssl.HAS_SSLv3)
    TLSv1 = str(ssl.HAS_TLSv1)
    TLSv1_1 = str(ssl.HAS_TLSv1_1)
    TLSv1_2 = str(ssl.HAS_TLSv1_2)
    TLSv1_3 = str(ssl.HAS_TLSv1_3)

    sql = 'SELECT id FROM `domains` WHERE `domains`=?'
    values = (hostname,)
    host_id = conn.execute(sql, values).fetchall()

    sql = 'SELECT MAX(`Time`) FROM `domain_time` WHERE domain_id=?'
    host_id = host_id[0][0]
    values = (host_id,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]
    table = PrettyTable()
    table.field_names = ["in_use", "SSLv2", "SSLv3", "TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"]
    table.add_row([in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3])
    print(table)
    
    sql = 'INSERT INTO `ssl_tls`(id, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, `Time`) VALUES (?,?,?,?,?,?,?,?,?)'
    values = (None, in_use, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, time)

    conn.execute(sql, values)
    conn.commit()
   

#verificar com outros outputs 
def db_insert_domain(conn, domain):
    """Funcao que insere o dominio na tabelas dos dominios"""
    try:
        if not conn or not domain:
            print("argumento em falta")
        ip = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            print(f"IP não encontrado para o dominio: {domain}")

        sql = 'INSERT or IGNORE INTO `domains`(id, domains, ip) VALUES (?,?,?)'
        values = (None, domain, ip)

        conn.execute(sql, values)
        conn.commit()
    except Exception:
        print("Impossivel inserir dominio na base de dados")

def db_insert_time_domain(conn, domain):
    """Funcao que insere a hora do scan dos dominios na tabela
    de tempos associada aos dominios"""
    try:
        sql='SELECT id FROM `domains` WHERE `domains`=?'
        values = (domain,)
        
        dom_id = conn.execute(sql, values).fetchall()
        dom_id = dom_id[0][0]

        sql = 'INSERT INTO `domain_time`(domain_id, `Time`) VALUES (?,?)'
        date = datetime.datetime.now()
        values = (dom_id, date)

        conn.execute(sql, values)
        conn.commit()
    except Exception:
        print("Impossivel inserir tempo na base de dados")

def blacklisted(conn, domain):
    """Funcao que procura dominios em blacklists"""
	
    print("\n" + "[+] Blacklists para o dominio: " + domain + " [+]")
    sql='SELECT id FROM `domains` WHERE `domains`=?'
    values = (domain,)
    domid = conn.execute(sql, values).fetchall()
    domid = domid[0][0]

    sql='SELECT MAX(`Time`) FROM `domain_time` WHERE domain_id=?'
    values=(domid,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]

    bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
       "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net","dnsbl.spfbl.net", "drone.abuse.ch", "drone.abuse.ch",
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

    my_resolver = dns.resolver.Resolver()
    try:
        ip = socket.gethostbyname(domain) 
    except Exception:
        print("Falha a obter ip do dominio")
        return
    
    for bl in bls:
        try:
            #my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ip).split("."))) + "." + bl
            my_resolver.timeout = 2
            my_resolver.lifetime = 2
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print(f'{ip} listado em {bl}' + f' ({answers[0]}: {answer_txt[0]})')

            blist = str(bl)
            sql = 'INSERT INTO `blacklist_domains`(id, domain_id, blacklist, Time) VALUES (?,?,?,?)'
            values = (None, domid, blist, time)
            conn.execute(sql, values)
            conn.commit()

        except dns.resolver.NXDOMAIN:
            #print(f'{domain} is not listed in {bl}')
            continue

        except dns.resolver.Timeout:
            print(f'WARNING: Timeout querying {bl}')

        except dns.resolver.NoNameservers:
            print(f'WARNING: No nameservers for {bl}')

        except dns.resolver.NoAnswer:
            print(f'WARNING: No answer for {bl}')

        except UnboundLocalError:
            print("Failed to resolve")

        except Exception:
            print("Falha a obter blacklist")


def db_insert_headers(conn, subdomain, subdomId, time):
    redirects = 6

    url = subdomain
    parsed = urlparse(url)
    if not parsed.scheme:
        # default to http if scheme not provided
        url = f'http://{url}' 

    headers_http = SecurityHeaders().check_headers(url, redirects)
    try:
        security_headers = []
        for header, value in headers_http.items():
            info = f"contains value \'{value['contents']}\'" if value['defined'] else "is missing"
            status = "OK" if value['warn'] == 0 else "WARN"
            security_headers.append((header, info, status))

            #print(f"Header: {header}, {info} - [ {status} ]")

        headers_https = SecurityHeaders().test_https(url)

        # HTTPS SUPPORTED?
        header = "HTTPS supported"
        status = "OK" if headers_https['supported'] else "FAIL"
        security_headers.append((header, None, status))
        #print(f"{header} - [{status}]")

        # VALID CERTIFICATE?
        header = "HTTPS valid certificate"
        status = "OK" if headers_https['certvalid'] else "FAIL"
        security_headers.append((header, None, status))
        #print(f"{header} - [{status}]")

        # HTTP REDIRECTS TO HTTPS?
        header = "HTTP -> HTTPS redirect"
        status = "OK" if SecurityHeaders().test_http_to_https(url, 5) else "FAIL"
        security_headers.append((header, None, status))
        #print(f"{header} - [{status}]")

        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Header", "Info", "Status"]
        sql = 'INSERT INTO `security_headers`(id, subdomain_id, header, info, status, `Time`) VALUES (?,?,?,?,?,?)'
        for (header, info, status) in security_headers:
            table.add_row([header, info, status])
            values = (None, subdomId, header, info, status, time )
            conn.execute(sql, values)
            conn.commit()
        print(table)

    except TimeoutError:
        print("db_insert_headers: TimeOut")
    except ConnectionError:
        print("db_insert_headers: Connection Error")
    except Exception:
        print("db_insert_headers: Falha a obter headers")



def check_sec_headers(conn, subdomain, domain):
    """Funcao que insere as informacoes sobre os cabecalhos de 
    seguranca na base de dados

    Args:
        domain (string): dominio no formato de string lido do 
        ficheiro dominios.txt
    """
    
    sql='SELECT id FROM `subdomains` WHERE `subdomain`=?'
    #sql='SELECT id FROM `subdomains_dump` WHERE `subdomain`=?'

    values = (subdomain,)
    subdomId = conn.execute(sql, values).fetchall()
    subdomId = subdomId[0][0]

    sql='SELECT id FROM `domains` WHERE `domains`=?'
    values = (domain,)
    domid = conn.execute(sql, values).fetchall()
    domid = domid[0][0]
    
    sql='SELECT MAX(`Time`) FROM `domain_time` WHERE domain_id=?'
    values=(domid,)
    time = conn.execute(sql, values).fetchall()
    time = time[0][0]

    db_insert_headers(conn, subdomain, subdomId, time)
    

def typo_squatting_api(conn, domain):
    try:
        new_url = domain.encode("utf-8").hex()

        api = requests.get(f"https://dnstwister.report/search/{new_url}/json")
        output = api.json()

        print("\n"+"[+] Typo-squatting para o dominio: " + domain + " [+]")

        table = PrettyTable()
        #table.align = "l"
        table.field_names = ["Dominio", "IP"]
        for fuzzy_domain in output[domain]["fuzzy_domains"]:
            ip = fuzzy_domain["resolution"]["ip"]
        
            if str(ip) != "False":
                squat_dom = fuzzy_domain["domain-name"]
                table.add_row([squat_dom, ip])
                
                sql='SELECT id FROM `domains` WHERE `domains`=?'
                values = (domain,)
                domid = conn.execute(sql, values).fetchall()
                domid = domid[0][0]

                sql='SELECT MAX(`Time`) FROM `domain_time` WHERE domain_id=?'
                values=(domid,)
                time = conn.execute(sql, values).fetchall()
                time = time[0][0]

                sql = 'INSERT INTO `typo_squatting`(id, domain_id, squat_dom, ip, Time) VALUES (?,?,?,?,?)'
                values = (None, domid, squat_dom, ip, time )
                conn.execute(sql, values)

                conn.commit()
        
        print(table)

    except requests.Timeout:
        return 'typo_squatting_api: Connection Timeout'
    except requests.ConnectionError:
        return 'typo_squatting_ap: Connection Lost'
    except requests.RequestException:
        return 'typo_squatting_api: Connection Failed'
    except Exception:
        return 'typo_squatting_api: typosquatting failed'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
        
        
