#!/usr/bin/env python3

import socket
import ssl
from datetime import datetime

bad_issuers = ("Symantec", "GeoTrust", "thawte", "RapidSSL", "VeriSign", "Equifax")
now_date = datetime.now()
one_day = 86400
timeout_seconds = 5
days_until_expired = 100

context = ssl.create_default_context()

def datify_date(the_date):
    return datetime.strptime(the_date[:20], '%b %d %H:%M:%S %Y')


def flatten(elem, leaves=None):
    """
    This accepts any nested lists and sublists, and expands it, so we have a flat structure, and we do not need to faff with optional nested lists.
    """
    leaves = []
    if isinstance(elem, tuple):
        for member in elem:
            leaves.extend(flatten(member))
    else:
        leaves.append(elem)
    return leaves


def check_expiration_date(ssl_expiration_date):
    """
    accepts expiration date, returns days left until expiration.
    """
    if type(ssl_expiration_date) is datetime:
        time_left = ssl_expiration_date - now_date
        return time_left.total_seconds() / one_day
    else:
        print(ssl_expiration_date + " type, is not datetime")
    return time_left.total_seconds() / one_day


def check_cert(domain):
    try:
        with socket.create_connection((domain, 443), timeout=timeout_seconds) as sock :
            with context.wrap_socket(sock, server_hostname=domain) as connection:
                result = connection.getpeercert()
               
                issuer = ' '.join(str(e) for e in flatten(result['issuer'][0:3]))
                valid_until = flatten(result['notAfter'])[0]
                start_date = flatten(result['notBefore'])[0]
                org_name = result['issuer'][1][0][1]
                result_dictionary = {
                    "domain": domain,
                    "issuer": issuer,
                    "start_date": start_date,
                    "valid_until": valid_until,
                    "org_name": org_name
                }
                valid_until = datify_date(result_dictionary['valid_until'])
                start_date = datify_date(result_dictionary['start_date'])
                
                #bad_list = []
                if check_expiration_date(valid_until) < days_until_expired:
                    """
                    if expiration days left less than value, put it in the list of dictionaries
                    """
                    reasons = {
                        "domain": domain,
                        "valid_until": valid_until.strftime("%Y-%m-%d"),
                        "start_date": start_date.strftime("%Y-%m-%d"),
                        "org_name": org_name,
                        "reason": "less than {} days left".format(int(check_expiration_date(valid_until)))
                    }
                    return reasons
                    
                if any(bad in issuer for bad in bad_issuers):
                    reasons = {
                        "domain": domain,
                        "valid_until": valid_until.strftime("%Y-%m-%d"),
                        "start_date": start_date.strftime("%Y-%m-%d"),
                        "org_name": org_name,
                        "reason": "issuer"
                    }
                
                    return reasons
                
                return {"domain": domain, "valid_until": "None",  "start_date": "None", "org_name": "None","reason": "None",}
                   
    except Exception as e:
        print(e)
        fail = {
            "domain": domain,
            "valid_until": "None",
            "start_date": "None",
            "org_name": "None",
            "reason": str(e)
        }
        return fail

