#!/usr/bin/env python3

#import os
import sys
#import dnstwist
import re
import requests
#import argparse


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
		exit(1)

	for (key,value) in enumerate(req.json()):
		subdomains.append(value['name_value'])

	print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))

	subdomains = sorted(set(subdomains))

	for subdomain in subdomains:
		print("[-]  {s}".format(s=subdomain))
		if output is not None:
			save_subdomains(subdomain,output)


#------------------------------------------------------
if __name__=="__main__":
    fl = open(sys.argv[1], "r").readlines() 
    
    for line in fl:
        domain=line.strip()

        subdomains(domain)
        
