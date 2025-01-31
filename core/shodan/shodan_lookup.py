#Requirements
import re
import shodan #needed for the Shodan API
from whois.parser import EMAIL_REGEX #needed to receive inputs as flags
import socket #used to obtain IP from domain name
import re
import time #used to sleep between API requests
import sys #needed to exit in case of error

#API keys setup
API_KEY_SHODAN = '9LUFXpzw0uGHTWjLr0Ll2RFCgMoVH4uK' #ItqMMRidUObWFTvkPKNgOpYffHbJ3msW'
shodan_api = shodan.Shodan(API_KEY_SHODAN)

#Lists
all_IPs=[] #saves all IPS found for domain and subdomains
subdomains_IPs = {} #dictionary that will store the found subdomains and their IPs
emails_list=[]

#Variables
domain="" #used to save the main domain
IP_domain="" #used to save the main IP of the domain

#insert_IP_in_general_list - removes the repeated IPS  and inserts them into the all_IPS list 
def insert_IP_in_general_list(IPtoInsert):
    if IPtoInsert not in all_IPs: #removes the repeated IPS 
        all_IPs.append(IPtoInsert) #inserts them into the all_IPS list 

#getIPbyDomainShodan - searches through shodan all IPs associated with a domain 
def getIPbyDomainShodan(domain_address): 
    try:
        domain = shodan_api.search(domain_address) #shodan API call
        time.sleep(2) #wait 2 seconds between requests to shodan API (only one request per second is allowed)
        try:
            for data in domain['matches']:
                print(data)
                if (data.get('ip_str')is not None): #get the domain or subdomain IP and return it
                    insert_IP_in_general_list(data.get('ip_str')) #removes the repeated IPS and inserts them into the all_IPS list 
        except KeyError:
            print("Service banner not found!")
    except shodan.APIError as e:
        print("API Error: {}".format(e))

#solve_subdomains - look up the IP of the subdomains, call the functioninsert_IP_in_general_list  
def solve_subdomains(subdomains_dict): 
    splitString="@"
    for i in subdomains_dict:
        if splitString in i:
            emails_list.append(i)
        else:
            try:   
                ip_address = socket.gethostbyname(i) #get from the ip of each subdomain
                insert_IP_in_general_list(ip_address) #removes the repeated IPS  and inserts them into the all_IPS list
                subdomains_IPs.update({i:ip_address})
            except:
                subdomains_IPs.update({i : "Not propagated"})
                pass

#IP_LOOKUP_SHODAN - search through shodan various information about certain IP. This information is added to a list
def IP_lookup_shodan(IP_address): 
    time.sleep(2) #wait 2 seconds between requests to shodan API (only one request per second is allowed)
    Results={} #dictionary where collected information is stored, if the information is ≠ of none
    try:
        ip = shodan_api.host(IP_address)
        if (ip.get('country_name') is not None): 
            Results.update({"Country":ip.get('country_name')}) #IP country information
        if (ip.get('org') is not None):
            Results.update({"Organization":ip.get('org')}) #IP organization information
        if len(ip.get('domains')) !=0:   
            Results.update({"Domains":ip.get('domains')}) #IP domain information
        if len(ip.get('hostnames')) !=0:  
            Results.update({"Hostnames":ip.get('hostnames')}) #IP hostnames information
        if (ip.get('isp') is not None):
            Results.update({"ISP":ip.get('isp')}) #IP ISP information
        if  len(ip.get('ports')) !=0:   
            Results.update({"Ports":ip.get('ports')}) #IP ports information
        try:
            for data in ip['data']:
                if (data.get('transport') is not None): 
                    Results.update({"Protocol":data.get('transport')}) #port protocol information
                if (data.get('product') is not None):
                    Results.update({"Service":data.get('product')}) ##port service information
                if (data.get('version') is not None): 
                    Results.update({"Version":data.get('version')}) #service version information                        
        except KeyError:
            print("Service banner not found!")
    except shodan.APIError as e:
        print("API Shodan Error: {}".format(e))
    return Results


def IP_validation(ip):
    pat = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
    test = pat.match(ip)
    if test:
        print ("Acceptable IP address.")
    else:
        print ("Unacceptable IP address. Please enter a valid IP.")
        sys.exit(0)

def domain_validation(domain):
    pat = re.compile("^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$")
    test = pat.match(domain)
    if test:
        print ("Acceptable domain address.")
   
    else:
        print ("Unacceptable domain address. Please enter a valid domain address.")
        sys.exit(0)

#To print dictionaries
def print_dictionaries(DictionarytoPrint):
    for key,value in DictionarytoPrint.items():
        if type(value) is dict:
            print(str(key))
            for chave,valor in value.items():
                print("\t"+str(chave) + ": " + str(valor))
        else:
            print(str(key) + ": " + str(value))


def main():
    #l = ["cybers3c.pt"]
    a= getIPbyDomainShodan("cybers3c.pt")
    print(a)    

main()