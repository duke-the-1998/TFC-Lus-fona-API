# Script para monitorização de IPs e domínios

## Monitorizador

### Primeiro correr:

```bash
pip3 install -r requirements.txt
```

### Correr o comando:

```bash
sudo python3 monitorizador.py ips.txt dominios.txt 
```

### Notas

+ A interface do comando masscan deve ser alterada 
+ impar a base de dados apenas na primera execução, depois comentar linha da main que tem a função deleteTabels()