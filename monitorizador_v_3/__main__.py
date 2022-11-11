#!/usr/bin/env python3

import os
import sys
from core import *
from script_harvester import harv

#cabeçalho com variaveis globais

if __name__=="__main__":
    
   # fips = open(sys.argv[1], "r").readlines() 
   fdominio = open(sys.argv[1], "r").readlines() 
 
   for line in fdominio:
      domain = line.strip()
      
      harv(domain)
    
      print("[+] ### Subdominios " + domain + " ### [+]")  
      print(subenum(domain, no_ip=True))
      
      print("\n"+"[+] ### ReverseDNS " + domain +" ### [+]")  
      print(reversedns(domain))
      
      print("\n"+"[+] ### Security Headers " + domain +" ### [+]")  
      print(grab(domain))
      
      print("\n"+"[+] ### DNS " + domain +" ### [+]")  
      print(fetch_dns(domain, cli=False))
      
      print("\n"+"[+] ### Shared DNS " + domain +" ### [+]")  
      print(fetch_shared_dns(domain))
      
      os.remove("results.json")
      os.remove("results.xml")
      