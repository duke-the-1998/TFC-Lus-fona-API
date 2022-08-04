#!/usr/bin/env python3

import nmap
import sys
import ipaddress
#import re 


def ipScan():
    #funcao que le um ficheiro de ip, verifica se sao validos e em caso de o ip ser valido
    #faz scan a esse ip
    nm = nmap.PortScanner()
    file = open(sys.argv[1], "r")

    while True:
       
        l = file.readlines()
        if not l:
            return "erro"
       
        for line in l:
            ip = line.strip()
            #resolver problema do strict (defaul ou igual a true nao funciona) 
            ip_address_obj = ipaddress.ip_network(ip, strict=False)
            print(nm.scan(line, arguments='-A -Pn -p-'))


if __name__=="__main__":
    ipScan()