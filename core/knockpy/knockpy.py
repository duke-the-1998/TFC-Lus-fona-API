#!/usr/bin/python3
# -*- coding: utf-8 -*-

from argparse import RawTextHelpFormatter
from colorama import Fore, Style
import concurrent.futures
from os import path
import socket
from . import dns_socket
import requests
import random
import bs4
import sys
import re
import os

config = {
    "attack": [
        "http"
    ],
    "ignore": [
        "127.0.0.1"
    ],
    "user_agent": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"
    ],
    "timeout": 3,
    "threads": 50,
    "wordlist": {
        "local": "wordlist.txt",
        "remote": [
            "google",
            "duckduckgo",
            "virustotal"
        ],
        "default": [
            "local",
            "remote"
        ]
    },
    "dns": "1.1.1.1",
    "api": {
        "virustotal": ""
    },
    "no_http_code": [],
    "report": {
        "save": True,
        "folder": "knockpy_report",
        "strftime": "%Y_%m_%d_%H_%M_%S"
    }
}

if hasattr(socket, "setdefaulttimeout"): 
    socket.setdefaulttimeout(config["timeout"])

class Request():
    def dns(target):
        try:
            if config["dns"]:
                return dns_socket._gethostbyname_ex(target, config["dns"])
            return socket.gethostbyname_ex(target)
        except:
            return []

    def https(url):
        headers = {"user-agent": random.choice(config["user_agent"])}
        try:
            resp = requests.get("https://"+url, headers=headers, timeout=config["timeout"])
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []
        
    def http(url):
        headers = {"user-agent": random.choice(config["user_agent"])}
        try:
            resp = requests.get("http://"+url, headers=headers, timeout=config["timeout"])
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []

    def bs4scrape(params):
        target, url, headers = params
        resp = requests.get(url, headers=headers, timeout=config["timeout"])
        
        pattern = "http(s)?:\/\/(.*)\.%s" % target
        subdomains = []
        if resp.status_code == 200:
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            for item in soup.find_all("a", href=True):
                if item["href"].startswith("http") and item["href"].find(target) != -1 and item["href"].find("-site:") == -1:
                    match = re.match(pattern, item["href"])
                    if match and re.match("^[a-zA-Z0-9-]*$", match.groups()[1]):
                        subdomains.append(match.groups()[1])
        return list(dict.fromkeys(subdomains))

class Wordlist():
    def local(filename):
        try:
            wlist = open(filename,'r').read().split("\n")
        except:
            _ROOT = os.path.abspath(os.path.dirname(__file__))
            filename = os.path.join(_ROOT, "", filename)
            wlist = open(filename,'r').read().split("\n")
        return filter(None, wlist)
    
    def google(domain):
        headers = {"user-agent": random.choice(config["user_agent"])}
        dork = "site:%s -site:www.%s" % (domain, domain)
        url = "https://google.com/search?q=%s&start=%s" % (dork, str(3))
        params = [domain, url, headers]
        try:
            return Request.bs4scrape(params)
        except Exception as e:
            return []

    def duckduckgo(domain):
        headers = {"user-agent": random.choice(config["user_agent"])}
        dork = "site:%s -site:www.%s" % (domain, domain)
        url = "https://duckduckgo.com/html/?q=%s" % dork
        params = [domain, url, headers]
        try:
            return Request.bs4scrape(params)
        except Exception as e:
            return []
        
    def get(domain):
        config_wordlist = config["wordlist"]
    
        config_api = config["api"]
        user_agent = random.choice(config["user_agent"])

        local, google, duckduckgo = [], [], []

        if "local" in config_wordlist["default"]:
            local = list(Wordlist.local(config_wordlist["local"])) if "local" in config_wordlist["default"] else []

        if "remote" in config_wordlist["default"]:
            google = list(Wordlist.google(domain)) if "google" in config_wordlist["remote"] else []
            duckduckgo = list(Wordlist.duckduckgo(domain)) if "duckduckgo" in config_wordlist["remote"] else []
        
        return local, google, duckduckgo

class Output():
    def progressPrint(text):
        if not text: text = " "*80
        text_dim = Style.DIM + text + Style.RESET_ALL
        sys.stdout.write("%s\r" % text_dim)
        sys.stdout.flush()
        sys.stdout.write("\r")
    
    def jsonizeRequestData(req, target):
       
        if len(req) == 3:
            subdomain, aliasList, ipList = req
            domain = subdomain if subdomain != target else ""
            
            data = {
                "target": target,
                "domain": domain,
                "alias": aliasList,
                "ipaddr": ipList
                }
            
        elif len(req) == 5:
            subdomain, aliasList, ipList, code, server = req
            domain = subdomain if subdomain != target else ""

            data = {
                "target": target,
                "domain": domain,
                "alias": aliasList,
                "ipaddr": ipList,
                "code": code,
                "server": server
                }

        else:
            data = {}
        
        return data

    def linePrint(data, max_len):
        """
        123.123.123.123   click.domain.com     click.virt.s6.exactdomain.com
        """ 

        # just a fix, print space if not domain
        _domain = " "*max_len if not data["domain"] else data["domain"]

        if len(data.keys()) == 4:
            spaceIp = " " * (16 - len(data["ipaddr"][0]))
            spaceSub = " " * ((max_len + 1) - len(data["target"]))
            _target = Style.BRIGHT + Fore.CYAN + data["target"] + Style.RESET_ALL if data["alias"] else data["target"]
            line = data["ipaddr"][0] +spaceIp+ _target +spaceSub+ _domain
        elif len(data.keys()) == 6:
            data["server"] = data["server"][:max_len]

            spaceIp = " " * (16 - len(data["ipaddr"][0]))
            spaceSub = " " * ((max_len + 1) - len(data["target"]))
            spaceCode = " " * (5 - len(str(data["code"])))
            spaceServer = " " * ((max_len + 1) - len(data["server"]))
            
            if data["code"] == 200:
                _code = Style.BRIGHT + Fore.GREEN + str(data["code"]) + Style.RESET_ALL
                _target = Style.BRIGHT + Fore.GREEN + data["target"] + Style.RESET_ALL
            elif str(data["code"]).startswith("4"):
                _code = Style.BRIGHT + Fore.MAGENTA + str(data["code"]) + Style.RESET_ALL
                _target = Style.BRIGHT + Fore.MAGENTA + data["target"] + Style.RESET_ALL
            elif str(data["code"]).startswith("5"):
                _code = Style.BRIGHT + Fore.RED + str(data["code"]) + Style.RESET_ALL
                _target = Style.BRIGHT + Fore.RED + data["target"] + Style.RESET_ALL
            else:
                _code = str(data["code"])
                _target = Style.BRIGHT + Fore.CYAN + data["target"] + Style.RESET_ALL if data["domain"] else data["target"]

            line = data["ipaddr"][0] +spaceIp+ _code +spaceCode+ _target +spaceSub+ data["server"] +spaceServer+ _domain

        return line

class Start():
   
    def arguments(target):

        domain = target

        if domain.startswith("http"): sys.exit("remove http(s)://")
        if domain.startswith("www."): sys.exit("remove www.")
        if domain.find(".") == -1: sys.exit("invalid domain")

        return domain

    def scan(max_len, domain, subdomain, percentage, results):
        ctrl_c = "(ctrl+c) | "

        #Output.progressPrint(ctrl_c + subdomain)
        target = subdomain+"."+domain
        Output.progressPrint(ctrl_c + str(percentage*100)[:4] + "% | " + target + " "*max_len)
        req = Request.dns(target)

        if not req: return None

        req = list(req)
        ip_req = req[2][0]

        if ip_req in config["ignore"]: return None

        # dns only
        if not "http" in config["attack"]:
            # print line and update report
            data = Output.jsonizeRequestData(req, target)
            print (Output.linePrint(data, max_len))
            
            del data["target"]
            
            return results.update({target: data})

        # dns and http(s)
        https = Request.https(target)
        
        if https:
            for item in https:
                req.append(item)
        else:
            http = Request.http(target)
            
            if http:
                for item in http:
                    req.append(item)
            else:
                req.append("")
                req.append("")

        # print line and update report
        data = Output.jsonizeRequestData(req, target)
        if data["code"] in config["no_http_code"]: return None
        print (Output.linePrint(data, max_len))
        #del data["target"]
        return results.update({target: data})

def knockpy(target):
    domain = target

    # wordlist
    Output.progressPrint("getting wordlist ...")
    local, google, duckduckgo = Wordlist.get(domain)
    wordlist = list(dict.fromkeys((local + google + duckduckgo)))
    wordlist = sorted(wordlist, key=str.lower)
    max_len = len(f"{max(wordlist, key=len)}.{domain}") if wordlist else sys.exit("\nno wordlist")

    if not wordlist: 
        sys.exit("no wordlist")

    # init
    len_wordlist = len(wordlist)
    results = {}

    # start
    with concurrent.futures.ThreadPoolExecutor(max_workers=config["threads"]) as executor:
        results_executor = {executor.submit(Start.scan, max_len, domain, subdomain, wordlist.index(subdomain)/len_wordlist, results) for subdomain in wordlist}
        
        for item in concurrent.futures.as_completed(results_executor):
            if item.result() != None:
                print (item.result())
    
    subs = list()
    for sub in results:
        subs.append(sub)

    return subs
