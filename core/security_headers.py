#!/usr/bin/env python3

import http.client
import re
import socket
import ssl

from urllib.parse import urlparse

class SecurityHeaders():
    """Classe com as funcoes sobre os cabecalhos de seguranca
    """
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):
        """ Risk evaluation function.
        Set header warning flag (1/0) according to its contents.
        Args:
            header (str): HTTP header name in lower-case
            contents (str): Header contents (value)
        """
        warn = 1

        if header == 'x-frame-options' and contents.lower() in ['deny', 'sameorigin']:
            warn = 0

        if header == 'strict-transport-security':
            warn = 0

        if header == 'content-security-policy':
            warn = 0

        if header == 'access-control-allow-origin' and contents != '*':
            warn = 0

        if header.lower() == 'x-xss-protection' and contents.lower() in ['1', '1; mode=block']:
            warn = 0

        if header == 'x-content-type-options' and contents.lower() == 'nosniff':
            warn = 0
        
        if header == 'x-powered-by' or header == 'server' and len(contents) <= 1:
            warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        hostname = parsed[1]
        sslerror = False

        conn = http.client.HTTPSConnection(hostname, context = ssl.create_default_context())
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:
            sslerror = True

        # if tls connection fails for unexcepted error, retry without verifying cert
        if sslerror:
            conn = http.client.HTTPSConnection(hostname, timeout=5, context = ssl._create_stdlib_context())
            try:
                conn.request('GET', '/')
                res = conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http' # default to http if protocl scheme not specified

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if protocol == 'http':
            conn = http.client.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print('HTTP request failed')
            return False
        except socket.timeout:
            print('HTTP request failed: Timeout')
            return False
        except:
            return False

        #Follow redirect
        if res.status >= 300 and res.status < 400  and follow_redirects > 0:
            for header in headers:
                if header[0].lower() == 'location':
                    return self.test_http_to_https(header[1], follow_redirects - 1)

        return False

    def check_headers(self, url, follow_redirects = 0):
        """funcao que procura informacao sobre os cabecalhos de seguranca"""
            
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''},
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''}
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]

        if protocol == 'http':
            conn = http.client.HTTPConnection(hostname, timeout=10)
        elif protocol == 'https':
            # on error, retry without verifying cert
            # in this context, we're not really interested in cert validity
            ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(hostname, context = ctx, timeout=10)
        else:
            """ Unknown protocol scheme """
            print("Protocolo desconhecido")
            return {}

        #atencao a este try!!!
        #adicionar timeout 10segs
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()

            """ Follow redirect """
            if res.status >= 300 and res.status < 400  and follow_redirects > 0:
                for header in headers:
                    if header[0].lower() == 'location':
                        redirect_url = header[1]
                        if not re.match('^https?://', redirect_url):
                            redirect_url = f'{protocol}://{hostname}{redirect_url}'
                        return self.check_headers(redirect_url, follow_redirects - 1)

            for header in headers:
                headerAct = header[0].lower()
                if headerAct in retval:
                    retval[headerAct] = self.evaluate_warn(headerAct, header[1])

            return retval

        except socket.gaierror:
            print('HTTP request failed')
            #return False
        except socket.timeout:
            print('HTTP request failed, socket timeout')
        except ConnectionRefusedError:
            print('HTTP request failed. ConnectionRefusedError.')
        except TimeoutError:
            print('HTTP request failed. TimeoutError')
        except ConnectionResetError:
            print('HTTP request failed. Connection Reset Error by peer')
        except ConnectionAbortedError:
            print('HTTP request failed. Connection Aborted Error')
        except:
            print('Erro ao verificar cabeçalhos de segurança')
           # return False