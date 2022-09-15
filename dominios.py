#!/usr/bin/env python3

import re
import socket
import sqlite3
import ssl
import sys
import urllib.request
from urllib.parse import urlparse

import requests
import socket

import securityheaders

#-------auxiliares-------------
def is_valid_domain(str):
 
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
     
    p = re.compile(regex)
 	 
    if str != None and re.search(p, str):
        return True
	

'''
def cleanDupLines(domain):
	lines_seen = set() # holds lines already seen
	outfile = "clean_"+domain+".txt"
	infile = domain+".txt"
	outfile = open(outfile, "w")
	for line in open(infile, "r"):
		if line not in lines_seen: # not a duplicate
			outfile.write(line)
			lines_seen.add(line)
	outfile.close()
	deleteFirstLine(domain)


def deleteFirstLine(domain):
	f = "clean_"+domain+".txt"

	with open(f, 'r') as fin:
		data = fin.read().splitlines(True)
	with open(f, 'w') as fout:
		fout.writelines(data[1:])
'''
#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + "\n")
		f.close()

def subdomains(domains):

	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)

	s = []
	subdomains = []
	target = clear_url(domains)
	output = domains+".txt"

	req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))

	if req.status_code != 200:
		print("[X] Information not available!") 
		return None

	conn.execute('''
            CREATE TABLE IF NOT EXISTS `Subdomains` (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                Domain_ID INTEGER,
                Subdomain TEXT,
                StartDate TEXT,
                EndDate TEXT,
                Country TEXT,
                CA TEXT,
                FOREIGN KEY (Domain_ID) REFERENCES `Domains`(ID)
            );
            ''')

	subdomain_info = list()
	for value in req.json():
		subdomains = str(value['name_value']).split("\n")
		
		for subdomain in subdomains: 
		
			if subdomain not in subdomain_info and not re.search("^[*.]", subdomain):
				subdomain_info.append(subdomain)
				
				startDate = value['not_before'].split("T")[0]
				endDate = value['not_after'].split("T")[0]
				country = value['issuer_name'].split(",")[0].split("=")[1]
				ca = value['issuer_name'].split(",")[1].split("=")[1]

				sql = 'SELECT ID FROM Domains WHERE Domains=?'
				values = (domains,)
				domID = conn.execute(sql, values).fetchall()
				domID = domID[0][0]

				sql = 'INSERT INTO `Subdomains`(ID, Domain_ID, Subdomain, StartDate, EndDate, Country, CA) VALUES (?,?,?,?,?,?,?)'
				values = (None, domID, subdomain, startDate, endDate, country, ca )
				conn.execute(sql, values)
				conn.commit()

	print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

'''
for subdomain in res_list:
		print("{s}".format(s=subdomain))

		if output is not None:
			save_subdomains(subdomain,output)
'''

#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `SSL/TLS` (
				ID INTEGER PRIMARY KEY,
				SSLv2 TEXT,
				SSLv3 TEXT,
				TLSv1 TEXT,
				TLSv1_1 TEXT,
				TLSv1_2 TEXT,
				TLSv1_3 TEXT,
				FOREIGN KEY (ID) REFERENCES `Domains`(ID)
		);
		''')

	context = ssl.create_default_context()
	
	with socket.create_connection((hostname, 443)) as sock:
		with context.wrap_socket(sock, server_hostname=hostname) as ssock:
			if ssock.version():
				#PERGUNTAR PELA VERSAO TLS FAVORITA
				print(ssock.version())
				print("TLSv1_3: "+str(ssl.HAS_TLSv1_3))
				print("TLSv1_2: "+str(ssl.HAS_TLSv1_2))
				print("TLSv1_1: "+str(ssl.HAS_TLSv1_1))
				print("TLSv1: "+str(ssl.HAS_TLSv1))
				print("SSLv2: "+str(ssl.HAS_SSLv2))
				print("SSLv3: "+str(ssl.HAS_SSLv3))

				TLSv1_3 = str(ssl.HAS_TLSv1_3)
				TLSv1_2 = str(ssl.HAS_TLSv1_2)
				TLSv1_1 = str(ssl.HAS_TLSv1_1)
				TLSv1 = str(ssl.HAS_TLSv1)
				SSLv2 = str(ssl.HAS_SSLv2)
				SSLv3 = str(ssl.HAS_SSLv3)

				sql = 'INSERT INTO `SSL/TLS`(ID, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 ) VALUES (?,?,?,?,?,?,?)'
				values = (None, SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3)
				
				conn.execute(sql, values)
				conn.commit()
				#print(ssock.getpeercert(binary_form=False))
			else:
				print("Not found")

#verificar com outros outputs 
def create_domains_table(domain):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `Domains` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				Domains TEXT
		);
		''')

	sql = 'INSERT INTO `Domains`(ID, Domains) VALUES (?,?)'
	values = (None, domain)
	
	conn.execute(sql, values)
	conn.commit()

def deleteTabels():
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	conn.execute(''' DROP TABLE IF EXISTS `Subdomains`;''')
	conn.execute(''' DROP TABLE IF EXISTS `SSL/TLS`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Domains`;''')
	
	conn.commit()

if __name__=="__main__":

	deleteTabels()

	fl = open(sys.argv[1], "r").readlines() 
    
	for line in fl:
		domain = line.strip()
		if is_valid_domain(domain):
			create_domains_table(domain)	
			subdomains(domain)
			ssl_version_suported(domain)
			securityheaders.secHead(domain)

