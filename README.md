# Monitorizador
# Script para monitorização de IPs e domínios

```
Existem duas versões deste monitorizador, monitorizadorDominios que analisa os dominios e imprime o resultado no terminal, e a segunda
versão em que analisa ip's e dominios e imprime o resultado no terminal e coloca tambem na base de dados.
```

### Primeiro correr:

```bash
pip3 install -r requirements.txt
```
### Correr o comando:

```bash
sudo python3 allFiles.py ips.txt dominios.txt 
```

## ATENÇÃO!!!

```bash
-A interface do comando masscan deve ser alterada 
-Limpar a base de dados apenas na primera execução, depois comentar linha da main que
tem a função deleteTabels() 
```
