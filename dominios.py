#!/usr/bin/env python3

#import os
import sys
#import dnstwist
import re
import requests
import socket
import ssl
#import argparse
#from urllib.parse import urlparse
#import http.client
#from urllib.parse import urlparse
#from http.client import HTTPConnection, HTTPSConnection

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
#TODO falta apagar primeira linha do ficheiro	


#------Subdominios-------------
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()

def save_subdomains(subdomain,output_file):
	with open(output_file,"a") as f:
		f.write(subdomain + '\n')
		f.close()

def subdomains(domains):

	subdomains = []
	target = clear_url(domains)
	output = domains+".txt"

	req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))

	if req.status_code != 200:
		print("[X] Information not available!") 
		#retirar este exit(1), substituir por return null
		exit(1)

	
	for value in req.json():
		subdomains.append(value['name_value'])

	print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

	subdomains = sorted(set(subdomains))
	
	'''
	key = value['name_value']
	info = {}
	startDate = value['not_before'].split("T")[0]
	endDate = value['not_after'].split("T")[0]
	cert = value['issuer_name']
	
	info[key].append('data de criacao: '+startDate, 'data de expiracao: '+endDate, 'issuer_name: '+cert)
	
	print(info)

	startDate = value['not_before'].split("T")[0]
	endDate = value['not_after'].split("T")[0]
	cert = value['issuer_name']
	print("Start Date: "+startDate)
	print("End Date: "+endDate)
	print("Cert: " + cert)
	inf = open("domainInfo_"+domain+".txt", "a")
	inf.write("Start Date: "+startDate+"\n")
	inf.write("End Date: "+endDate+"\n")
	inf.write("Cert: " +cert+"\n")
	inf.close()
'''
	
	for subdomain in subdomains:
		print("[-]  {s}".format(s=subdomain))

		if output is not None:
			save_subdomains(subdomain,output)


#---------Webcheck------------
#----------https--------------
def ssl_version_suported(hostname):

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
				print(ssock.getpeercert(binary_form=False))
			else:
				print("Not found")

#verificar com outros outputs 

if __name__=="__main__":
	fl = open(sys.argv[1], "r").readlines() 
    
	for line in fl:
		domain = line.strip()
			
		subdomains(domain)
	#	cleanDupLines(domain)
	
		ssl_version_suported(domain)
		
