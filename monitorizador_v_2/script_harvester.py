#!/usr/bin/env python3
import os
import sys
import json

limit = "500"
filename = "results"
tool = "theHarvester.py"

#lista targets ler de um ficheiro
#sources menos utilizadas = ["anubis", "baidu","binaryedge", "bingapi", "bufferoverun", "censys", "fullhunt", "github-code",]

listSourcesAAA = [ "bing", "certspotter", "crtsh", "dnsdumpster", "duckduckgo",  "google", "hackertarget", 
               "hunter", "intelx", "linkedin", "linkedin_links", "n45ht", "omnisint", "otx", "pentesttools", "projectdiscovery", 
               "qwant", "rapiddns", "rocketreach", "securityTrails", "spyse", "sublist3r", "threatcrowd", "threatminer", "trello", 
               "twitter", "urlscan", "virustotal", "yahoo", "zoomeye" ]

listSources = [ "certspotter", "dnsdumpster"]

results = []
def scan_harvester(target, limit, filename):
    """
    TODO: escrever o que a funcao faz
    """ 
    for source in listSources:
        print("############### " + source + " ###############")
        command = tool + " -d " + target + " -l " + limit + " -b " + source + " -f " + filename + ""

        try:
            print("[+] Running the theharvester:  %s" % command)
            os.system(command)

            with open("results.json", "r") as input:
                json_result = json.load(input)
                results.append(json_result)        

        except:
            print("erros")
  
if __name__=="__main__":
    targets = open(sys.argv[1], "r").readlines()

    for target in targets:
        scan_harvester(target, limit, filename)
        
    
    with open(target + ".json", "a") as output:  
        json.dump(results, output, indent=4)
    
    os.remove("results.json")
    os.remove("results.xml")