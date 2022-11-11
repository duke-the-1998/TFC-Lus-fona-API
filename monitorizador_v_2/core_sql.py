#!/usr/bin/env python3

import sqlite3
from urllib.parse import urlparse
from core import *
from delete_sql import delete_tabels
from create_sql import create_tabels
import json
 
#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"

domain = "edp.pt"

def webeye_subdomain_to_sql(domain):
    delete_tabels()      
    create_tabels()
    
    db = database_name
    con = sqlite3.connect(db)
    
    
    subdom_list = subenum(domain, no_ip=False)
    print(subdom_list)
    for item in subdom_list:
        subdom = item[0]
        ip = item[1]
        
        sql = 'INSERT INTO `subdomains_webeye`(ID, subdomain, ip) VALUES (?,?,?)'
        values = (None, subdom, ip)
        con.execute(sql, values)
        con.commit()

def harvester_json_to_sql(domain):
    
    f = open(domain+'.json',)
 
    data = json.load(f)
 
    for i in data:
        print(i.get('hosts'))
 

    f.close()
   
    
    
#webeye_subdomain_to_sql(domain)
harvester_json_to_sql(domain)