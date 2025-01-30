# CyberS3c 🖥️🐉


# API para monitorização de IPs e domínios

## Conteúdos

- [Introdução](#Introdução)
- [Instalação](#instalação)
- [Endpoints](#Endpoints)
- [Informações obtidas](#Informações)
- [Exemplos](#Exemplos)
- [Notas](#Notas)


## Introdução

Este projeto é uma **API de monitorização de IPs e domínios**, desenvolvida para auxiliar a CyberS3c onde vai ser integrada
na plataforma VIRIATUS na análise e acompanhamento de ameaças e vulnerabilidades. A API permite verificar a reputação  de 
IPs e domínios e obter informações detalhadas sobre cada entidade monitorizada tal como os protocolos usados ou até mesmo 
os subdominios associados a um dominio principal.

Criada para uso interno e integração com outras ferramentas de segurança, esta API fornece respostas rápidas e estruturadas, facilitando
a recolha de informação externa de uma empresa.


## Instalação
  
### Pré-Requisitos
+ Python 3.10  
+ Git  
+ Uma IDE à escolha (recomendado VSCode ou PyCharm)

### Clonar o repositório
Abra o terminal e execute : 
```
$ git clone https://github.com/duke-the-1998/TFC-Lusofona-API
```

### Criar e Ativar o Ambiente Virtual
**No Windows:**
```
python -m venv venv
venv/Scripts/activate
```

**No Linux:**
```
python -m venv venv
source venv/bin/activate
```

### Instalar Dependências
O repositório já inclui algumas das dependências no ficheiro requirements.txt:
```
python -r requirements.txt
```

### Executar a API
Correr o comando: 
```
python monitorizador.py
```


## Endpoints da API

### Monitorização de IPs
**Rota:**`monitorizador/IP/{ip}/{interface}`
+ **Descrição:** Retorna informações de forma detalhada de um determinado IP fornecido  
+ **Parâmetros:**
  + **ip(obrigatório):** O endereço Ip a ser analisado
  + **interface(opcional):** Interface de rede a ser considerada. Default: enp0s3 ou en0
+ **Exemplo de Requisição:**
  ```
  https://localhost/monitorizador/IP/193.137.75.244/enp0s3
  ```
  
### Monitorização de Domínios
**Rota:**`monitorizador/DOM/{dominio}/{interface}`
+ **Descrição:** Retorna informações de forma detalhada de um determinado domínio fornecido  
+ **Parâmetros:**
  + **dominio(obrigatório):** O domínio a ser analisado
  + **interface(opcional):** Interface de rede a ser considerada. Default: enp0s3 ou en0
+ **Exemplo de Requisição:**
  ```
  https://localhost/monitorizador/DOM/ulusofona.pt/enp0s3
  ```


## Informações Obtidas
### IPs
+ Procura de portos abertos (masscan)
+ Pesquisa de certificados SSL/TLS
+ Enumeração de protocolos
+ Estado dos portos (open, filterd, ...)
+ Blacklist IPs


### Domínios
+ Procura de subdomínios (subdomínios e certificados) com crt.sh
+ Verifica a blacklist dos ips.
+ versões de ssl e tls
+ Verificar cabeçalhos de segurança.
+ Typosquatting


### Examples

#### Domínios

```
{
  "dominios": [
    {
      "domain": "teste.pt",
      "ip": "1.1.1.1",
      "ssl_tls": {
        "SSLv2": "False",
        "SSLv3": "False",
        "TLSv1": "True",
        "TLSv1_1": "True",
        "TLSv1_2": "True",
        "TLSv1_3": "True",
        "Time": "2025-01-30 09:36:10",
        "in_use": "TLSv1.3"
      },
      "subdominios": [
        {
          "days_left": "SSL error",
          "headers": [
            {
              "header": "x-frame-options",
              "info": "contains value 'DENY'",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "strict-transport-security",
              "info": "is missing",
              "status": "WARN",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "access-control-allow-origin",
              "info": "is missing",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "content-security-policy",
              "info": "contains value 'script-src 'report-sample' 'nonce-DNbXc3IIImyovob2sUTwew' 'unsafe-inline';object-src 'none';base-uri 'self';report-uri /cspreport'",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "x-xss-protection",
              "info": "contains value '1; mode=block'",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "x-content-type-options",
              "info": "contains value 'nosniff'",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "x-powered-by",
              "info": "is missing",
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "server",
              "info": "contains value 'GSE'",
              "status": "WARN",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "HTTPS supported",
              "info": null,
              "status": "FAIL",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "HTTPS valid certificate",
              "info": null,
              "status": "FAIL",
              "time": "2025-01-30 09:37:18"
            },
            {
              "header": "HTTP -\u003E HTTPS redirect",
              "info": null,
              "status": "OK",
              "time": "2025-01-30 09:37:18"
            }
          ],
          "ip": "2.2.2.2",
          "nome": "gmail.teste.pt",
          "org_name": "None",
          "start_date": "None",
          "time": "2025-01-30 09:37:17",
          "valid_until": "None"
        },
      ],
      "time": "2025-01-30 09:36:10"
    }
  ]
}
```

#### IPs

```
{
  "ips": [
    {
      "hosts": [
        {
          "address": "1.1.1.1",
          "name": null,
          "port": [
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 80,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 443,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2052,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2053,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2082,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2083,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2086,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2087,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2095,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 2096,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 8080,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 8443,
              "protocol": "tcp",
              "ssl": true,
              "state": "open"
            },
            {
              "date": "2025-01-30 09:32:54",
              "description": "open",
              "portNumber": 8880,
              "protocol": "tcp",
              "ssl": false,
              "state": "open"
            }
          ]
        }
      ],
      "revrse_ip_lookup": {
        "reverse_ip": null,
        "time": "2025-01-30 09:32:54"
      }
    }
  ]
}
```

### Notas 
Não está ativo:
+ **theHarvester**, dado que precisa de apis (encontra-se em core/unused)
+ **hackertarget**, dado que precisa de apis


