#!/usr/bin/env python3

# Imports necessários
import datetime
import sys
import time
import dns.resolver
import requests
import yaml
import concurrent.futures
from core.crtsh.crtsh import crtshAPI
from core.crtsh.crtsh_cert_info import check_cert
from core.knockpy.knockpy import knockpy
from core.security_headers import *
from prettytable import PrettyTable
from core.shodan.my_shodan import search_domain_info, shodan_subdomains
jsonDominio = {}


def get_dicDominio():
    """
        Esta funcão é usada no utils.py para o dicionário ser transformado mais á frente no json

        Retorna:
            Retorna o dicionário com as informações do domínio.

        """
    return jsonDominio


def is_valid_domain(dominio):
    """
        Verifica se um domínio é válido de acordo com uma regular expression

        Parâmetros:
            dominio (str): Nome do domínio a ser verificado

        Retorna:
            Verdadeiro se o domíno for válido, falso caso contrário

        """
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\.)" + "+[A-Za-z]{2,6}"
    p = re.compile(regex)
    return bool(dominio != None and re.search(p, dominio))


# ------Subdominios-------------
def clear_url(target):
    """
        Limpa o URL para obter apenas o nome do domínio.

        Parâmetros:
            target (str): URL a ser limpo

        Retorna:
            Nome do domínio limpo
        """
    return re.sub('.*www\.', '', target, 1).split('/')[0].strip().lower()


def simplify_list(lista):
    """
        Simplifica uma lista de listas, removendo duplicados.

        Parâmetros:
            lista (List): Lista de listas a ser simplificada

        Retorna:
            Lista simples e sem duplicados
        """
    try:
        flat_list = [item for sublist in lista for item in sublist]
        return list(set(flat_list))
    except Exception:
        print("Erro ao fazer flatten da lista de subdominios")


def get_crtsh_subdomains(target):
    """
        Obtém os subdomínios de um domínio a partir do crt.sh.

        Parâmetros:
            target (str): Domínio alvo

        Retorna:
            Lista de subdomínios encontrados

      """
    print("crtsh working")
    req_json = None

    for _ in range(3):
        req_json = crtshAPI().search(target)
        if req_json: break
        time.sleep(1)

    if not req_json:
        print(f"Pesquisa ao crt.sh falhou para {target}")

    subdomains = [str(value['name_value']).split("\n") for value in req_json]
    print("Acabo crtsh")
    return simplify_list(subdomains)

#procurar alternativa para o subdomains existentes
def get_all_subdomains(target, existent_subdomains):
    """
        Obtém todos os subdomínios a partir de um domínio.
        Utiliza várias fontes, como crt.sh, knockpy e hackertarget.
        Utiliza também threads para minimizar o tempo de resposta.

        Parâmetros:
            target (str): Domínio alvo

        Retorna:
            Lista de subdomínios encontrados e validados

        """



    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(knockpy, target),
            executor.submit(get_crtsh_subdomains, target),
            executor.submit(subdomains_finder_dnsdumpster, target),
            executor.submit(shodan_subdomains, target)
        ]

        subdomains_knockpy = futures[0].result()
        subdomains_crtsh = futures[1].result()
        subdomains_hackertarget = futures[1].result()
        sub_shodan = futures[2].result()



    all_subdomains_notclean = list(set( subdomains_crtsh + subdomains_knockpy +
                                       subdomains_hackertarget + sub_shodan + existent_subdomains))  # TODO adicionar hackertarget ao tuplo, falta chave da api
    all_subdomains_unique = list(filter(lambda s: not s.startswith('*'), all_subdomains_notclean))


    return list(filter(lambda s: is_valid_domain(s), all_subdomains_unique))


def check_reason(reason):
    """
        Verifica e retorna uma mensagem mais compreensivel com base na razão de falha.

        Parâmetros:
            reason (str): Mnesagem de erro original

        Retorna:
            Mensagem de erro interpretada
        """
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

    # EOF occurred in violation of protocol (_ssl.c:1131)
    elif "EOF" in reason:
        return "SSL error"

    else:
        return reason


def subdomains_finder(domain, existent_subdomains):
    """
        Encontra e valida subdomínios para um domínio.

        Parâmetros:
            domain (str): Domínio alvo

        Esta função não retorna nada, mas coloca no dicionário dos dominios todas as informações sobre os subdominios
        """
    try:
        if not domain:
            print("argumento em falta")

        target = clear_url(domain)

        all_subdomains = get_all_subdomains(target, existent_subdomains)

        jsonDominio["subdominios"] = []
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

            dt = datetime.datetime.now()
            subdominios = {
                "nome": subdomain,
                "ip": ip,
                "start_date": start_date,
                "valid_until": valid_until,
                "days_left": days_left,
                "org_name": org_name,
                "time": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "headers": insert_headers(subdomain)
            }

            jsonDominio["subdominios"].append(subdominios)

            print(f"[+] Cabecalhos de Seguranca: {subdomain} [+]\n")

    except Exception:
        print("Falha a obter subdominios")


# procurar chaves no ficheiro yaml
# retorna dict
def api_keys():
    """
        Obtém as chaves da API a partir do ficheiro YAML.

        Retorna:
            Dicionário com as chaves das APIs
        """
    try:
        with open("./core/api_keys_e_configs.yaml", 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']
    except FileNotFoundError:
        print("Ficheiro de chaves das APIs não foi encontrado")
        return {}


# retorna string
def hackertarget_key():
    """
       Obtém a chave da API do Hackertarget.

       Retorna:
            Chave da API do Hackertarget
       """
    return api_keys()['hackertarget']['key']


def subdomains_finder_dnsdumpster(domain):
    """
        Obtém subdomínios através da API do Hackertarget (DNSDumpster).

        Parâmetros:
            domain (str): Domínio alvo

        Retorna:
            Lista de subdomínios encontrados
      """
    print("hackertarget working")
    try:
        key = hackertarget_key()
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}&apikey={key}")
        lines = api.text.split("\n")
        if '' in lines:
            lines.remove('')

        print("Acabou hackertarget")
        # subdominio,ip
        return [line.split(',')[0] for line in lines if "," in line]

    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
    except Exception:
        print(f"hackertarget nao encontrou subdominios para: {domain}")
        return []


# ---------Webcheck------------
# ----------https--------------
def ssl_version_suported(hostname):
    """
        Verifica quais as versões SSL/TLS que estão a ser usadas.

        Parâmetros:
            hostname (str): Nome do domínio a ser verificado
        """
    if not hostname:
        print("Argumento em falta")

    print(f"\n[!] ---- TARGET: {hostname} ---- [!] \n")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock, context.wrap_socket(sock,
                                                                                    server_hostname=hostname) as ssock:
            if ssock.version():
                check_ssl_versions(ssock)
            else:
                print("Certificado nao encontrado")
    except Exception:
        print(f"Dominio nao alcancavel: {hostname}")


def check_ssl_versions(ssock):
    """
        Verifica quais as versões SSL/TLS que estão a ser usadas para o hostname.

        Parâmetros:
            ssock: Conexão SSL
        """
    in_use = ssock.version()
    SSLv2 = str(ssl.HAS_SSLv2)
    SSLv3 = str(ssl.HAS_SSLv3)
    TLSv1 = str(ssl.HAS_TLSv1)
    TLSv1_1 = str(ssl.HAS_TLSv1_1)
    TLSv1_2 = str(ssl.HAS_TLSv1_2)
    TLSv1_3 = str(ssl.HAS_TLSv1_3)

    dt = datetime.datetime.now()

    jsonDominio["ssl_tls"] = {
        "in_use": in_use,
        "SSLv2": SSLv2,
        "SSLv3": SSLv3,
        "TLSv1": TLSv1,
        "TLSv1_1": TLSv1_1,
        "TLSv1_2": TLSv1_2,
        "TLSv1_3": TLSv1_3,
        "Time": dt.strftime("%Y-%m-%d %H:%M:%S")
    }

    table = PrettyTable()
    table.field_names = ["in_use",
                         "SSLv2",
                         "SSLv3",
                         "TLSv1",
                         "TLSv1_1",
                         "TLSv1_2",
                         "TLSv1_3", ]

    table.add_row([in_use,
                   SSLv2,
                   SSLv3,
                   TLSv1,
                   TLSv1_1,
                   TLSv1_2,
                   TLSv1_3])

    print(table)


# verificar com outros outputs
def db_insert_domain(domain):
    """
        Insere o domínio na estrutura de dados jsonDominio.

        Parãmetros:
            domain (str): Nome do domínio a ser inserido
        """

    jsonDominio.clear()
    if not domain:
        print("Argumento em falta!")
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        print(f"IP não encontrado para o dominio: {domain}")

    dt = datetime.datetime.now()
    jsonDominio['domain'] = domain
    jsonDominio['ip'] = ip
    jsonDominio['time'] = dt.strftime("%Y-%m-%d %H:%M:%S")


def blacklisted(domain):
    """
        Função que procura dominios em blacklists.

        Parâmetros:
            domain(str): Domínio a ser verificado nas blacklists
       """

    print("\n" + "[+] Blacklists para o dominio: " + domain + " [+]")

    bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
           "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
           "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
           "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
           "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
           "dnsbl.sorbs.net", "dnsbl.spfbl.net", "drone.abuse.ch", "drone.abuse.ch",
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

    jsonDominio["blacklist_domains"]: []

    for bl in bls:
        try:
            # my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ip).split("."))) + "." + bl
            my_resolver.timeout = 2
            my_resolver.lifetime = 2
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print(f'{ip} listado em {bl}' + f' ({answers[0]}: {answer_txt[0]})')

            blist = str(bl)

            dt = datetime.datetime.now()
            blacklist = {
                "blacklist": blist,
                "time": dt.strftime("%Y-%m-%d %H:%M:%S")
            }

            jsonDominio["blacklist_domains"].append(blacklist)


        except dns.resolver.NXDOMAIN:
            # print(f'{domain} is not listed in {bl}')
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


def insert_headers(subdomain):
    """
        Verifica e insere os cabeçalhos de segurança para um subdomínio.

        Parâmetros:
            Subdomínio a ser verificado

        """
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

        headers_https = SecurityHeaders().test_https(url)

        # HTTPS SUPPORTED?
        header = "HTTPS supported"
        status = "OK" if headers_https['supported'] else "FAIL"
        security_headers.append((header, None, status))
        # print(f"{header} - [{status}]")

        # VALID CERTIFICATE?
        header = "HTTPS valid certificate"
        status = "OK" if headers_https['certvalid'] else "FAIL"
        security_headers.append((header, None, status))
        # print(f"{header} - [{status}]")

        # HTTP REDIRECTS TO HTTPS?
        header = "HTTP -> HTTPS redirect"
        status = "OK" if SecurityHeaders().test_http_to_https(url, 5) else "FAIL"
        security_headers.append((header, None, status))
        # print(f"{header} - [{status}]")

        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Header", "Info", "Status"]

        security_headers_json = []

        dt = datetime.datetime.now()

        for (header, info, status) in security_headers:
            table.add_row([header, info, status])
            security_headers_json2 = {
                "header": header,
                "info": info,
                "status": status,
                "time": dt.strftime("%Y-%m-%d %H:%M:%S")
            }

            security_headers_json.append(security_headers_json2)

        print(table)

        return security_headers_json


    except TimeoutError:
        print("insert_headers: Timeout")
    except ConnectionError:
        print("insert_headers: ConnectionError")
    except Exception:
        print("insert_headers: Falha a obter headers")


def typo_squatting_api(domain):
    try:
        new_url = domain.encode("utf-8").hex()

        api = requests.get(f"https://dnstwister.report/search/{new_url}/json")
        output = api.json()

        print("\n" + "[+] Typo-squatting para o dominio: " + domain + " [+]")

        table = PrettyTable()
        # table.align = "l"
        table.field_names = ["Dominio", "IP"]

        jsonDominio["typo_squatting"] = []

        for fuzzy_domain in output[domain]["fuzzy_domains"]:
            ip = fuzzy_domain["resolution"]["ip"]

            if str(ip) != "False":
                squat_dom = fuzzy_domain["domain-name"]
                table.add_row([squat_dom, ip])

                dt = datetime.datetime.now()
                typo_squatting = {
                    "squat_dom": squat_dom,
                    "ip": ip,
                    "time": dt.strftime("%Y-%m-%d %H:%M:%S")
                }

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
