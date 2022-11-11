import socket
import time
import sys
import requests
import string
import json as _json
from datetime import datetime
from collections.abc import Iterable
from typing import Union
from concurrent.futures import ThreadPoolExecutor

# Helper Functions
def _listtodict(lst):
    it = iter(lst)
    response = dict(zip(it, it))
    return response


def extract_pagelinks(host: str, cli=False) -> Union[list, None]:
    '''Extract All Pagelinks From Website'''
    api = requests.get(f'https://api.hackertarget.com/pagelinks/?q={host}').text.split('\n')
    api.remove('')
    if cli:
        for count, result in enumerate(api, start=1):
            print(f'{count}). {result}')
    else:
        return api


########util
def fetch_shared_dns(host: str, cli=False) -> Union[list,None]:
    '''Find Shared DNS Server from Website'''
    api = requests.get(f'https://api.hackertarget.com/findshareddns/?q={host}').text.split('\n')
    if cli:
        for count, result in enumerate(api, start=1):
            print(f'{count}). {result}')
    else:
        return api

########util
def reversedns(host: str) -> str:
    '''Reverse DNS Lookup'''
    realip = socket.gethostbyname(host)
    api =  requests.get(f'https://api.hackertarget.com/reversedns/?q={realip}').text.strip(f'{realip} ')
    return api

"""Usar masscan para obter lista de portos descobertos/ comparar com NMAP 
"""

def scan(target: str, port: Union[int, Iterable], start: int=0, dev_mode: bool=False, api :bool=False, threads: int=100) -> Union[tuple,None]:
    '''Python Port Scanner Enumerate all Open Ports of Given Host:\n
    Use dev_mode = True,  if You want response in list.\n
    Use API = True if you are making api
    '''
    try:
        realip = socket.gethostbyname(target)
        lists = [f'\nPyPort started at {datetime.utcnow().strftime("%d-%b-%Y %I:%M %p")}<br/>','PORTS   |   SERVICE']
        on = time.time()
        def scan_port(port) -> Union[str,list]: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = sock.connect_ex((socket.gethostbyname(realip), port))
            if not conn:
                if dev_mode:
                    lists.append(f'{port}/{socket.getservbyport(port)}')
                elif api:
                    lists.append(f'{port}/tcp | {socket.getservbyport(port)}')
                else:
                    print(f'{port}/tcp\t   |   {socket.getservbyport(port)}\t|   open   |')
            sock.close()

        def execute():
            with ThreadPoolExecutor(max_workers=threads) as host:
                if isinstance(port, Iterable):
                    host.map(scan_port, port)
                    return 'Scan Finished.'
                else:
                    host.map(scan_port, range(start, port))
                if not dev_mode and not api:
                    return f'\nScan done: 1 IP address (1 host up) scanned at rate {round(time.time()-on, 2)}s/port.'
                else:
                    return f'IP: {realip}'
        runner = execute()

        if dev_mode:
            return runner,lists[2:]
        elif api:
            return runner, lists
        else:
            return runner

    except socket.gaierror:
        return 'Unable To resolve target IP'
    except socket.error:
        return f'{target} is Unreachable'
    except KeyboardInterrupt:
        return sys.exit('Process Stopped Exiting: 1')

#######Util ---subdominios e respetivos IPs
def subenum(host: str, cli=False, no_ip=True) -> Union[list, dict, None]:
    """Enumerate a list of subdomains for given host"""
    try:
        DOMAINS = []
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}")
        lines = api.text.split("\n")
        if '' in lines:
            lines.remove('')
        if cli:
            cliresponse = [x.split(',')[0] if no_ip else x.split(',') for x in lines]
            for i,v in enumerate(cliresponse, start=1):
                if no_ip:
                    print(f'{i}). {v}')
                else:
                    print(f"{v[0].ljust(60,' ')} | {v[1].rjust(40,' ')}  << ({i})")
        else:
            if no_ip:
                return list(line.split(',')[0] for line in lines)
            else:
                for line in lines:
                    x = line.split(',')
                    for j in x:
                        DOMAINS.append(j)
                return _listtodict(DOMAINS)

    except requests.ConnectionError:
        return 'Connection Lost: Retry Again'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

#######util
def reverseip(host: str, cli=False) -> Union[str, None]:
    '''Reverse IP Lookup For Gievn Host'''
    realip = socket.gethostbyname(host)
    api = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={realip}",headers={'Connection':'close'}).text
    if cli:
        result = api.split("\n")
        for x,y in enumerate(result, start=1):
            print(f'{x}). {y}')
    else:
        return api

#####Util info sobre cabeçalhos de seguranca
def grab(host: str, schema='http://', cli=False) -> Union[dict, None]:
    '''Grab headers of a given host (Banner Grabbing)'''
    try:
        api = requests.get(schema+host)
        if cli:
            for x,y in api.headers.items():
                print(f'{x}: {y}')
        else:
            return dict(api.headers)
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
"""
def whois(target: str) -> str:
     #Whois Lookup for a Given Host
    try:
        response = requests.get(f"https://api.webeye.ml/whois/?q={target}").text
        return response
    except (requests.ConnectionError, requests.ConnectTimeout):
        return 'Unable to get result'
    except Exception:
        print("something went wrong")
"""
        
"""
def geoip(host: str, cli=False) -> Union[dict, None]:
    '''Geolocation Enumeration for a given host'''
    realip = socket.gethostbyname(host)
    api : dict = requests.get(f'http://ip-api.com/json/{realip}?fields=66846715').json()
    if not cli:
        return api
    else:
        for c,(k,v) in enumerate(api.items(), start=1):
            print(f'{c}). {k}: {v}')
"""

"""
def enumerate_waf(host: str) -> Union[str, list, bool]:
    '''Enumerate list of Firewall protecting host, False if not found...'''
    try:
        target = requests.get(f"https://api.webeye.ml/waf/?q={host}")
        socket.gethostbyname(host)
        waf = target.json()['manufacturer'] if target.json()['waf'] else False
        return (waf if waf else False)

    except socket.gaierror:
        return "Unable to connect with host"
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
"""

def fetch_dns(host: str, cli=False) -> Union[None, list]:
    '''Start DNS lookup Of a given host'''
    try:
        api =  requests.get(f"https://api.hackertarget.com/dnslookup/?q={host}",headers={'Connection':'close'}).text
        if cli:
            print(api)
        else:
            result = api.split("\n")
            return result
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

def isitdown(host: str) -> dict:
    """Check whether the site is down for everyone or not..."""
    try:
        response = requests.get(f'https://isitdown.site/api/v3/{host}').json()
        return response
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
"""
def is_honeypot(host: str, score: bool=False):
    '''Return Probablity of Honeypot between [0.0 - 1.0] based on Shodan Honeyscore...'''
    try:
        target = socket.gethostbyname(host)
        honey = f'https://api.shodan.io/labs/honeyscore/{target}?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by'
        try:
            result = requests.get(honey).text
            if 'error' in result:
                return f'No information Available for: {target}'
        except:
            result = None
            return "Couldn't scan Host:- {}".format(target)
        if score:
            return float(result)
        else:
            return f'Honeypot Probablity: {float(result)*100}%'

    except socket.gaierror:
        return 'Unable to resolve address'
    except socket.error:
        return f'{target} is Unreachable'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')
"""