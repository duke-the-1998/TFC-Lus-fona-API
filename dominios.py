#!/usr/bin/env python3


import sys
import re
import requests
import socket
import ssl
from urllib.parse import urlparse
import urllib.request

import sqlite3

#-------auxiliares-------------
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
		#retirar este exit(1), substituir por return null
		#exit(1)
		return None

	#print(req.json())
	subdomain_info = {}
	for value in req.json():
		sd = value['name_value']
        
		cs = sd.split("\n")
		for c in cs: 
			# c «e um subdominio valido
			if not c in subdomain_info.keys():
				subdomain_info[c] = {"not_before": value['not_before'].split("T")[0],
									"not_after" : value['not_after'].split("T")[0],
									"country" : value['issuer_name'].split(",")[0].split("=")[1],
									"ca" : value['issuer_name'].split(",")[1].split("=")[1]
									} 
	

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

				for key,values in subdomain_info.items():
					subdm = key
					startDate = values["not_before"]
					endDate = values["not_after"]
					country = values["country"]
					ca = values["ca"]


				sql='SELECT ID FROM Domains WHERE Domains=?'
				values=(domains,)
				domID = conn.execute(sql, values).fetchall()
				domID=domID[0][0]

				sql = 'INSERT INTO `Subdomains`(ID, Domain_ID, Subdomain, StartDate, EndDate, Country, CA) VALUES (?,?,?,?,?,?,?)'
				values = (None, domID, subdm, startDate, endDate, country, ca )
				conn.execute(sql, values)
				conn.commit()

	print(subdomain_info.keys())

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
				TLSv1_3 TEXT,
				TLSv1_2 TEXT,
				TLSv1_1 TEXT,
				TLSv1 TEXT,
				SSLv2 TEXT,
				SSLv3 TEXT,
				FOREIGN KEY (ID) REFERENCES `Domains`(ID)
		);
		''')

	context = ssl.create_default_context()
	
	with socket.create_connection((hostname, 443)) as sock:
		with context.wrap_socket(sock, server_hostname=hostname) as ssock:
			if ssock.version():
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
	
				sql = 'INSERT INTO `SSL/TLS`(ID, TLSv1_3, TLSv1_2, TLSv1_1, TLSv1, SSLv2, SSLv3 ) VALUES (?,?,?,?,?,?,?)'
				values = (None, TLSv1_3, TLSv1_2, TLSv1_1, TLSv1, SSLv2, SSLv3)
				
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

		create_domains_table(domain)	
		subdomains(domain)
	#	cleanDupLines(domain)
	
		ssl_version_suported(domain)
	#	deleteFirstLine(domain)

