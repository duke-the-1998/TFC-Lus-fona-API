#!/usr/bin/env python3

import socket
import ssl
from datetime import datetime

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
    now_date = datetime.now()
    one_day = 86400
    if type(ssl_expiration_date) is not datetime:
        print(f"{ssl_expiration_date} type, is not datetime")
        return None

    time_left = ssl_expiration_date - now_date
    return int(time_left.total_seconds() / one_day)

def check_cert(domain):
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as connection:
                return check_cert_output(connection, domain)
                
    except Exception as e:
        return {"domain": domain, "valid_until": "None", "start_date": "None", "org_name": "None", "reason": str(e)}


def check_cert_output(connection, domain):
    result = connection.getpeercert()
    valid_until = flatten(result['notAfter'])[0]
    start_date = flatten(result['notBefore'])[0]
    
    flat_issuers = flatten(result['issuer'])
    index = flat_issuers.index("organizationName")
    org_name = flat_issuers[index + 1] if index else None

    valid_until = datify_date(valid_until)
    start_date = datify_date(start_date)

    return {
        "domain": domain,
        "valid_until": valid_until.strftime("%Y-%m-%d"),
        "start_date": start_date.strftime("%Y-%m-%d"),
        "org_name": org_name,
        "reason": check_expiration_date(valid_until),
    }
