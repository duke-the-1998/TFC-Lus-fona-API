#!/usr/bin/env python3

import sqlite3
#from ail_typo_squatting import runAll, subdomain
from bs4 import BeautifulSoup
from urllib.parse import urlparse

#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

def deleteTabels():
    """Funcao que apaga todas as tabelas da base de dados"""
    
    db = database_name
    conn = sqlite3.connect(db)
    conn.execute(''' DROP TABLE IF EXISTS `BlacklistDomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `SecurityHeaders`;''')
    conn.execute(''' DROP TABLE IF EXISTS `SSL/TLS`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Subdomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `DomainTime`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Blacklist`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Port`;''')
    conn.execute(''' DROP TABLE IF EXISTS `ReverseIP`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `Host`;''')

    conn.commit()
    