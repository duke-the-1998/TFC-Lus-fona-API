import shodan


SHODAN_API_KEY = '9LUFXpzw0uGHTWjLr0Ll2RFCgMoVH4uK'
api = shodan.Shodan(SHODAN_API_KEY)

#Funcao para obter subdominos 
def shodan_subdomains(domain):

    try:
        results = api.search(f'hostname:{domain}')
        
        subdomains = set()
        for result in results['matches']:
            subdomain = result['hostnames'][0] if result['hostnames'] else None
            if subdomain and subdomain.endswith('.' + domain):
                subdomains.add(subdomain)
        return list(subdomains)
    except shodan.APIError as e:
        print(f'Erro na API do Shodan: {e}')
        return []




# Funcao para pesquisar informações associadas a um dominio
def search_domain_info(domain):
    try:
        results = api.search('hostname:' + domain)
        
        ips = set()
        subdomains = set()
        security_headers = set()
        technologies = set()
        for result in results['matches']:
            ip_str = result['ip_str']
            ips.add(ip_str)
            subdomain = result['hostnames'][0] if result['hostnames'] else None
            if subdomain and subdomain.endswith('.' + domain):
                subdomains.add(subdomain)
            security_info = result.get('http', {}).get('security', None)
            if security_info:
                headers = security_info.get('headers', None)
                if headers:
                    for header_name, header_value in headers.items():
                        security_headers.add(f"{header_name}: {header_value}")
            data = result.get('data', None)
            if data:
                for technology in data.split('\n'):
                    technologies.add(technology)
        return ips, subdomains, security_headers, technologies
    except shodan.APIError as e:
        print('Erro: %s' % e)

# Pesquisa informacoes relacionadas com IP     
def search_ip_info(ip):
    try:
        result = api.host(ip)
        # Processa os resultados
        ip_info = {
            'ip': result['ip_str'],
            'portas': [],
            'banners': [],
            'localizacao': result.get('location', None),
            'organizacao': result.get('org', None),
            'hostname': result.get('hostnames', None),
            'sistema_operativo': result.get('os', None),
            'tecnologias': set()
        }
        for banner in result['data']:
            porta = banner['port']
            protocolo = banner['transport']
            ip_info['portas'].append({'porta': porta, 'protocolo': protocolo})
            ip_info['banners'].append(banner)
            ip_info['tecnologias'].add(banner.get('product', ''))
            ip_info['tecnologias'].add(banner.get('version', ''))
            ip_info['tecnologias'].add(banner.get('devicetype', ''))
        return ip_info
    except shodan.APIError as e:
        print('Erro: %s' % e)



def main_dom(domain):
    
    ips, subdomains, security_headers, technologies = search_domain_info(domain)
    if ips:
        print("Endereços IP associados ao domínio '{}':".format(domain))
        for ip in ips:
            print(ip)
    else:
        print("Nenhum endereço IP encontrado para o domínio '{}'. Verifique se o domínio está correto.".format(domain))

    if subdomains:
        print("\nSubdomínios associados ao domínio '{}':".format(domain))
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("Nenhum subdomínio encontrado para o domínio '{}'. Verifique se o domínio está correto.".format(domain))

    if security_headers:
        print("\nCabeçalhos de segurança encontrados no domínio '{}':".format(domain))
        for header in security_headers:
            print(header)
    else:
        print("Nenhum cabeçalho de segurança encontrado para o domínio '{}'. Verifique se o domínio está correto.".format(domain))

    if technologies:
        print("\nTecnologias utilizadas no domínio '{}':".format(domain))
        for tech in technologies:
            print(tech)
    else:
        print("Nenhuma tecnologia encontrada para o domínio '{}'. Verifique se o domínio está correto.".format(domain))
        

def main_ip(ip):
    
    ip_info = search_ip_info(ip)
    if ip_info:
        print("Informações associadas ao endereço IP '{}':".format(ip_info['ip']))
        print("Portos abertos:")
        for porta_info in ip_info['portas']:
            print("Porta: {}, Protocolo: {}".format(porta_info['porta'], porta_info['protocolo']))
        #print("\nBanners dos serviços:")
        #for banner in ip_info['banners']:
        #    print(banner)
        print("\nLocalização Geográfica:", ip_info['localizacao'])
        print("Organização:", ip_info['organizacao'])
        print("Hostname:", ip_info['hostname'])
        print("Sistema Operativo:", ip_info['sistema_operativo'])
        print("Tecnologias Utilizadas:")
        for tech in ip_info['tecnologias']:
            print(tech)
    else:
        print("Nenhuma informação encontrada para o endereço IP '{}'. Verifique se o endereço IP está correto.".format(ip))

#ip = '65.21.239.46'
#domain = 'cybers3c.pt' 
#main_dom(domain)
#main_ip(ip)
#print(shodan_subdomains(domain))
