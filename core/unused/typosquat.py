#!/usr/bin/env python3

import os
import subprocess
import dnstwist
import dns.resolver
from ail_typo_squatting import runAll, subdomain
import math

#from asyncio.timeouts import timeout
#import dnspython as dns


def typo_squatting_twist(d):
    data = dnstwist.run(domain=d, registered=False, format=None)
    print(data)

#Typo-Squatting recorrendo ah biblioteca ail-typo-squatting
def typo_squatting(domain):

    #db = "monitorizadorIPs.db"
   # conn = sqlite3.connect(db)
	
    resultList = list()
    formatoutput = "text"
    pathOutput = "."
    #try:
    resultList = runAll(domain=domain, formatoutput=formatoutput, pathOutput=pathOutput, limit=math.inf, verbose=False)
    print(resultList)
  
   # for name in resultList:
      #  print(name)
   #     try:
    ##       result = dns.resolver.resolve(name, 'A')
    #        print(result)
            # Printing record
          #  command = "whois " + name

          #  print("[+] Running the whois enumeration:  %s" % command)
           # os.system(command)
            #record = subprocess.check_output(["whois", name])

            # write each whois record to a file {domain}.txt
'''            
            with open(domain+"_record.txt", 'a') as f:
                if not str(record).__contains__("No Match"):
                    f.write(str(record)+"\n")
                    
                    sql = 'INSERT INTO `Domains`(ID, Domains) VALUES (?,?)'
	                values = (None, domain)
	
                    conn.execute(sql, values)
                    conn.commit()
                    '''
           # for val in result:
           #     print('A Record : ', val.to_text())
           # print(w)   
          #  r = open(domain+"_record.txt", "a")
          #  r.write(str(os.system(command))+"\n")

       # except:
        #        print('WARNING: Timeout querying ')

    #except:
    #    print("Connection error")


def dnsresolve(domain): 
    # Finding A record
    fl = domain+".txt"
    
    with open (fl, "r") as squatFile:
       # sf = squatFile.readlines()

        for line in squatFile.readlines():
            print(line)
            try:

                my_resolver = dns.resolver.Resolver()
               
                my_resolver.timeout = 1
                my_resolver.lifetime = 1
                answers = my_resolver.query(line, "A")
                answer_txt = my_resolver.query(line, "MX")

                print(answers)
                print(answer_txt)

                #resultA = dns.resolver.query(line, 'A')
                #resultMX = dns.resolver.query(line, 'MX')
               # print(resultA)
                #print(resultMX)
                # Printing record
                #for val in resultA:
                #    print('A Record : ', val.to_text())
    
            except dns.resolver.Timeout:
                print('WARNING: Timeout querying ')
            
            except dns.resolver.NXDOMAIN:
                print("NXDOMAIN exception")
       
            except dns.resolver.NoNameservers:
                print('WARNING: No nameservers for ' + line)
                
            except dns.resolver.NoAnswer:
                print('WARNING: No answer for ' + line)
#nao funciona
def opensquat():
    command = "python3 /home/cybers3c/opensquat/opensquat.py"

    print("[+] Running the opensquat typosquatting tool:  %s" % command)
    os.system(command)
    
###DNSTWISTER API's
    """
    {
        "domain_fuzzer_url":"https://dnstwister.report/api/fuzz/{domain_as_hexadecimal}",
    "domain_to_hexadecimal_url":"https://dnstwister.report/api/to_hex/{domain}",
    "google_safe_browsing_url":"https://dnstwister.report/api/safebrowsing/{domain_as_hexadecimal}",
    "ip_resolution_url":"https://dnstwister.report/api/ip/{domain_as_hexadecimal}",
    "parked_check_url":"https://dnstwister.report/api/parked/{domain_as_hexadecimal}",
    "url":"https://dnstwister.report/api/",
    "whois_url":"https://dnstwister.report/api/whois/{domain_as_hexadecimal}"
    }
    """
      
if __name__=="__main__":
    domain = "cybers3c.pt"

   # opensquat()

#    typo_squatting_twist(domain)
#    typo_squatting(domain)
#    dnsresolve(domain)
