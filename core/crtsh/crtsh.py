#!/bin/env python3
"""
This is the (unofficial) Python API for crt.sh website.

Using this code, you can retrieve subdomains.
"""

import requests, json

class crtshAPI(object):
    """crtshAPI main handler."""

    def search(self, domain, wildcard=True, expired=True):
        """
        Search crt.sh for the given domain.

        domain -- Domain to search for
        wildcard -- Whether or not to prepend a wildcard to the domain
                    (default: True)
        expired -- Whether or not to include expired certificates
                    (default: True)

        Return a list of objects, like so:

        {
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
            "name_value": "hatch.uber.com",
            "min_cert_id": 325717795,
            "min_entry_timestamp": "2018-02-08T16:47:39.089",
            "not_before": "2018-02-08T15:47:39"
        }
        """
        base_url = "https://crt.sh/?q={}&output=json"
        if not expired:
            base_url += "&exclude=expired"
        if wildcard and "%" not in domain:
            domain = f"%.{domain}"
        url = base_url.format(domain)

        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        req = requests.get(url, headers={'User-Agent': ua})

        if req.ok:
            try:
                content = req.content.decode('utf-8')
                return json.loads(content)
            except ValueError:
                return json.loads("[{}]".format(content.replace('}{', '},{')))
            except Exception as err:
                print("Error retrieving information.")
        return None
