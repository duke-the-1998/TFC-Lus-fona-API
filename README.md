
# Script para monitorização de IPs e domínios

# Monitorizador_v_1  
Primeira versão do script de monitorização.

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

# Monitorizador_v_2  
Segunda versão do script de monitorização onde o codigo foi separado em vários ficheiro para ser mais fácil a sua 
compreensão e manutenção.
Contém tambem algumas alterações em relação ao primeiro script.

### Primeiro correr:  

```bash
pip3 install -r requirements.txt
```
### Correr o comando:  

```bash
sudo python3 __main__.py ips.txt dominios.txt 
```

## ATENÇÃO!!!

```bash
-A interface do comando masscan deve ser alterada 
-Limpar a base de dados apenas na primera execução, depois comentar linha da main que
tem a função deleteTabels() 
```

# Monitorizador_v_3  
Versão do script monitorizador que usa as ferramentas theHarvester e webeye para analise de dominios  

Imprime o resultado do the harvester no terminal assim como o resultado do webeye  

Guarda o output do the harvester num ficheiro JSON.  

#### problema na API hackertarget  

### Correr o comando:  

```bash
python3 __main__.py ips.txt dominios.txt 
```
