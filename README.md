# Script para monitorização de IPs e domínios

## Monitorizador

### Primeiro correr:

```bash
pip3 install -r requirements.txt
```

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
python3 monitorizador.py -t IP -f ips.txt -d monitorizadorIPs.db 
```

É possível definir a interface de rede com o `-i`

### Notas

+ A interface do comando masscan deve ser alterada 
+ impar a base de dados apenas na primera execução, depois comentar linha da main que tem a função deleteTabels()