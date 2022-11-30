# Script para monitorização de IPs e domínios

## Monitorizador

### Primeiro correr:

```bash
sudo pip3 install -r requirements.txt
sudo apt install masscan
sudo apt install sqlite3
sudo apt install libxslt1-dev libxml2

# util: browser para o sqlite
sudo apt install sqlitebrowser
```

Caso o pip install não funcione pode ser pelo ipv6: https://stackoverflow.com/questions/57992691/pip-hangs-on-starting-new-https-connection
### Correr o comando:
Obter help
```bash
python3 monitorizador.py -h 
```
Correr para dominios

```bash
python3 monitorizador.py -t DOM -f dominios.txt -d monitorizadorIPs.db 
```
Correr com IP:
```bash
sudo python3 monitorizador.py -t IP -f ips.txt -d monitorizadorIPs.db 
```

É possível definir a interface de rede com o `-i`


## Informação Obtida
### IPs
Imprime e mete na base de dados.
+ Procura de portos abertos (masscan)
+ Pesquisa de certificados SSL/TLS
+ Enumeração de protocolos
+ Estado dos portos (open, filterd, ...)
+ Blacklist IPs

### Dominios
Imprime e mete na base de dados.

O que faz:
+ Procura de subdomínios (subdomínios e certificados) com crt.sh
+ Verifica a blacklist dos ips.
+ versões de ssl e tls
+ Verificar cabeçalhos de segurança.

Não está ativo:
+ theHarvester, dado que precisa de apis (encontra-se em core/unused)
+ Typosquatting, implementado mas é muito lento.


# TODO
+ limpar typosquatting.py
