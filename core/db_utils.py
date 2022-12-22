#!/usr/bin/env python3

import sqlite3

def create_tabels(database_name):
    """Funcao que cria todas as tabelas da base de dados"""
    conn = sqlite3.connect(database_name)
    conn.execute("PRAGMA foreign_keys = on")
    # ips
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `host` (
            `host_id` INTEGER PRIMARY KEY AUTOINCREMENT,
            `address` TEXT UNIQUE NOT NULL,
            `Name`	TEXT
    );
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS `port` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id   INTEGER,
            `time` TIMESTAMP,
            `port`	INTEGER,
            `protocol`	TEXT,
            `description`	TEXT,
            `state`	TEXT,
            `ssl`	INTEGER,
            FOREIGN KEY (host_id, `time`) REFERENCES `time`(host_id, `time`)
    );
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS `ip_time` (
            host_id INTEGER,
            `time` TIMESTAMP NOT NULL,
            PRIMARY KEY(`time`)
            FOREIGN KEY (host_id) REFERENCES `Host`(`host_id`)
    );
    ''')

    conn.execute('''
            CREATE TABLE IF NOT EXISTS `reverse_ip` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                `reverse_ip`	TEXT,
                `time` TIMESTAMP,
                FOREIGN KEY (host_id, `time`) REFERENCES `time`(host_id, `time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `blacklist_ip` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            `blacklist`	TEXT,
            `time` TIMESTAMP,
            FOREIGN KEY (host_id, `time`) REFERENCES `time`(host_id, `time`)
    );
    ''')
    
    #dominios
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `domains` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domains TEXT UNIQUE NOT NULL
    );
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `domain_time` (
            domain_id  INTEGER,
            `time` TIMESTAMP,
            PRIMARY KEY (`time`)
            FOREIGN KEY (domain_id) REFERENCES `domains`(`id`)
    );
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `subdomains` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            subdomain TEXT,
            start_date TEXT,
            valid_until TEXT,
            days_left TEXT,
            org_name Text,
            time TIMESTAMP,
            
            FOREIGN KEY (domain_id, time) REFERENCES `domain_time`(domain_id, `time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `subdomains_dump` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            subdomain TEXT,
            ip TEXT,
            time TIMESTAMP,
            
            FOREIGN KEY (domain_id, time) REFERENCES `domain_time`(domain_id, `time`)
        );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `ssl_tls` (
            id INTEGER PRIMARY KEY,
            in_use TEXT,
            SSLv2 TEXT,
            SSLv3 TEXT,
            TLSv1 TEXT,
            TLSv1_1 TEXT,
            TLSv1_2 TEXT,
            TLSv1_3 TEXT,
            `time` TIMESTAMP,
            FOREIGN KEY (id, `time`) REFERENCES `domain_time`(domain_id, `time`)
    );
    ''')
    
    conn.execute('''
            CREATE TABLE IF NOT EXISTS `blacklist_domains` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER,
                blacklist TEXT,
                `time` TIMESTAMP,

                FOREIGN KEY (domain_id, `time`) REFERENCES `domain_time`(domain_id, `time`)
                );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `security_headers` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain_id INTEGER,
            header TEXT,
            info TEXT,
            status TEXT,
            `time` TIMESTAMP,
            
            FOREIGN KEY (`time`) REFERENCES `domain_time`(`time`)
            FOREIGN KEY (subdomain_id) REFERENCES `subdomains`(id)
            );
        ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS `typo_squatting` (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            squat_dom TEXT,
            ip TEXT,
            fuzzer TEXT,
            `time` TIMESTAMP,
            
            FOREIGN KEY (`time`) REFERENCES `domain_time`(`time`)
            FOREIGN KEY (domain_id) REFERENCES `domains`(id)
            );
        ''')


def delete_tabels(database_name):
    """Funcao que apaga todas as tabelas da base de dados"""
    
    conn = sqlite3.connect(database_name)
    conn.execute(''' DROP TABLE IF EXISTS `typo_squatting`;''')
    conn.execute(''' DROP TABLE IF EXISTS `blacklist_domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `security_headers`;''')
    conn.execute(''' DROP TABLE IF EXISTS `ssl_tls`;''')
    conn.execute(''' DROP TABLE IF EXISTS `subdomains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `subdomains_dump`;''')
    conn.execute(''' DROP TABLE IF EXISTS `domain_time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `domains`;''')
    conn.execute(''' DROP TABLE IF EXISTS `blacklist_ip`;''')
    conn.execute(''' DROP TABLE IF EXISTS `port`;''')
    conn.execute(''' DROP TABLE IF EXISTS `reverse_ip`;''')
    conn.execute(''' DROP TABLE IF EXISTS `ip_time`;''')
    conn.execute(''' DROP TABLE IF EXISTS `host`;''')

    conn.commit()
    