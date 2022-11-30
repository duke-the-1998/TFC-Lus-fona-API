#!/usr/bin/env python3
import os
import sys
import json

THEHARVESTER = "theHarvester.py"

#lista targets ler de um ficheiro
#sources menos utilizadas = ["anubis", "baidu","binaryedge", "bingapi", "bufferoverun", "censys", "fullhunt", "github-code",]

listSourcesAAA = [ "bing", "certspotter", "crtsh", "dnsdumpster", "duckduckgo",  "google", "hackertarget", 
               "hunter", "intelx", "linkedin", "linkedin_links", "n45ht", "omnisint", "otx", "pentesttools", "projectdiscovery", 
               "qwant", "rapiddns", "rocketreach", "securityTrails", "spyse", "sublist3r", "threatcrowd", "threatminer", "trello", 
               "twitter", "urlscan", "virustotal", "yahoo", "zoomeye" ]

listSources = [ "certspotter", "dnsdumpster"]


def scan_harvester(target): 
    results = []
    output_file_name = "results"

    for source in listSources:
        print("############### " + source + " ###############")
        command = THEHARVESTER + " -d " + target  + " -b " + source + " -f " + output_file_name + ""

        try:
            print("[+] Running the theharvester:  %s" % command)
            os.system(command)

            with open(output_file_name + ".json", "r") as input:
                json_result = json.load(input)
                results.append(json_result)   
                    
            os.remove(output_file_name + ".json")
            os.remove(output_file_name + ".xml")

            return results

        except:
            print("scan_harvester: falha a correr, dominio=" + target)
        
        return None
  
if __name__=="__main__":
    targets = open(sys.argv[1], "r").read().splitlines()

    for target in targets:
        results = scan_harvester(target)
        
        with open(target + ".json", "a") as output:  
            json.dump(results, output, indent=4)
