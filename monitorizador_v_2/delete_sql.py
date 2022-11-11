#!/usr/bin/env python3

import sqlite3

#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

def delete_tabels():
    """Funcao que apaga todas as tabelas da base de dados"""
    
    db = database_name
    conn = sqlite3.connect(db)
    #conn.execute(''' DROP TABLE IF EXISTS `subdomains_webeye`;''')
    conn.execute(''' DROP TABLE IF EXISTS `blacklist_domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `security_headers`;''')
    conn.execute(''' DROP TABLE IF EXISTS `ssl_tls`;''')
    conn.execute(''' DROP TABLE IF EXISTS `subdomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `domain_time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `blacklist_ip`;''')
    conn.execute(''' DROP TABLE IF EXISTS `port`;''')
    conn.execute(''' DROP TABLE IF EXISTS `reverse_ip`;''')
    conn.execute(''' DROP TABLE IF EXISTS `time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `host`;''')

    conn.commit()
    