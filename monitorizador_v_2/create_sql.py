#!/usr/bin/env python3

import sqlite3

#cabeçalho com variaveis globais
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"
#nome dos ficheiros

def create_tabels():
    """Funcao que cria todas as tabelas da base de dados"""
    conn = sqlite3.connect(database_name)
    conn.execute("PRAGMA foreign_keys = on")
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `host` (
            `HostID` INTEGER PRIMARY KEY AUTOINCREMENT,
            `Address`	TEXT,
            `Name`	TEXT
    );
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS `port` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            HostID   INTEGER,
            `Time` TIMESTAMP,
            `Port`	INTEGER,
            `Protocol`	TEXT,
            `Description`	TEXT,
            `State`	TEXT,
            `SSL`	INTEGER,
            FOREIGN KEY (HostID, `Time`) REFERENCES `time`(HostID, `Time`)
    );
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS `time` (
            HostID   INTEGER,
            `Time` TIMESTAMP,
            PRIMARY KEY (HostID, `Time`),
            FOREIGN KEY (HostID) REFERENCES `Host`(`HostID`)
    );
    ''')

    conn.execute('''
            CREATE TABLE IF NOT EXISTS `reverse_ip` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                HostID INTEGER,
                `ReverseIP`	TEXT,
                `Time` TIMESTAMP,
                FOREIGN KEY (HostID, `Time`) REFERENCES `time`(HostID, `Time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `blacklist_ip` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            HostID INTEGER,
            `Blacklisted`	TEXT,
            `Time` TIMESTAMP,
            FOREIGN KEY (HostID, `Time`) REFERENCES `time`(HostID, `Time`)
    );
    ''')
    
    #dominios
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `domains` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Domains TEXT
    );
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `domain_time` (
            DomainID   INTEGER,
            `Time` TIMESTAMP,
            PRIMARY KEY (DomainID, `Time`),
            FOREIGN KEY (DomainID) REFERENCES `domains`(`ID`)
    );
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `subdomains` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Domain_ID INTEGER,
            Subdomain TEXT,
            StartDate TEXT,
            EndDate TEXT,
            Country TEXT,
            CA TEXT,
            Time TIMESTAMP,
            
            FOREIGN KEY (Domain_ID, Time) REFERENCES `domain_time`(DomainID, `Time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `subdomains_dump` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Domain_ID INTEGER,
            Subdomain TEXT,
            ip TEXT,
            Time TIMESTAMP,
            
            FOREIGN KEY (Domain_ID, Time) REFERENCES `domain_time`(DomainID, `Time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `ssl_tls` (
            ID INTEGER PRIMARY KEY,
            in_use TEXT,
            SSLv2 TEXT,
            SSLv3 TEXT,
            TLSv1 TEXT,
            TLSv1_1 TEXT,
            TLSv1_2 TEXT,
            TLSv1_3 TEXT,
            `Time` TIMESTAMP,
            FOREIGN KEY (ID, `Time`) REFERENCES `domain_time`(DomainID, `Time`)
    );
    ''')
    
    conn.execute('''
            CREATE TABLE IF NOT EXISTS `blacklist_domains` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                DomainID INTEGER,
                Blacklist TEXT,
                `Time` TIMESTAMP,

                FOREIGN KEY (DomainID, `Time`) REFERENCES `domain_time`(DomainID, `Time`)
                );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `security_headers` (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Subdomain_ID INTEGER,
            Header TEXT,
            Info TEXT,
            Status TEXT,
            `Time` TIMESTAMP,
            
            FOREIGN KEY (`Time`) REFERENCES `domain_time`(`Time`)
            FOREIGN KEY (Subdomain_ID) REFERENCES `subdomains`(ID)
            );
        ''')

