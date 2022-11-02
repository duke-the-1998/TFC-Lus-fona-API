#!/usr/bin/env python3

import os
import sys

limit = "500"
filename = "results"

#lista targets ler de um ficheiro
#sources menos utilizadas = ["anubis", "baidu","binaryedge", "bingapi", "bufferoverun", "censys", "fullhunt", "github-code",]

listSourcesAAA = [ "bing", "certspotter", "crtsh", "dnsdumpster", "duckduckgo",  "google", "hackertarget", 
               "hunter", "intelx", "linkedin", "linkedin_links", "n45ht", "omnisint", "otx", "pentesttools", "projectdiscovery", 
               "qwant", "rapiddns", "rocketreach", "securityTrails", "spyse", "sublist3r", "threatcrowd", "threatminer", "trello", 
               "twitter", "urlscan", "virustotal", "yahoo", "zoomeye" ]

listSources = ["bing","certspotter"]

def scan_harvester(target, limit, filename):
    with open(target + ".json", "a") as o:
        o.write("["+"\n")
        
    for source in listSources:
        print("############### " + source + " ###############")
        command = "theHarvester.py -d " + target + " -l " + limit + " -b " + source + " -f " + filename + ""

        try:
            print("[+] Running the theharvester:  %s" % command)
            os.system(command)
                        
            with open("results.json", "r") as input:
                with open(target + ".json", "a") as output:
                    for line in input:
                        string = "\"" + source + "\"" + ":" + line
                        x = "{" + string + "},"  
                     #   print(x)    
                        output.write(x+"\n")

        except:
            print("erros")
        
    

def format_file(target):
    f = open(target + ".json")
 
    lines = f.readlines()
    f.close()

    data = lines[len(lines)-1]

    temp = list(data) 
    temp[len(data)-2] = "\n]"

    data = ''.join(temp)

    lines[len(lines)-1] = data

    f = open(target + ".json", "w")
    f.writelines(lines)
    f.close()
  
    
if __name__=="__main__":
    targets = open(sys.argv[1], "r").readlines()
    
    for target in targets:
        scan_harvester(target, limit, filename)
        format_file(target)
    
    os.remove("results.json")
    os.remove("results.xml")