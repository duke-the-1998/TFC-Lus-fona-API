# Funções não usadas
Estão aqui algumas funções não usadas no código do monitorizador, mas poderão ser úteis


## script_harvester.py
> Script para automatizar o the Harvester

Este script recebe um ficheiro com uma lista de targets, o nome do ficheiro pode ser mudado;  
Guarda o resultado num ficheiro JSON com o nome do target;  
Imprime o resultado no terminal.  

### Como correr:

```bash
python3 script_harvester.py targets.txt
```

### Limitações:
- Não verifica se os inputs/targets estão bem formados;  
- Podem existir valores duplicados, isto acontece porque as varias sources podem ter ouputs semelhantes;  
- Não tem chaves de api definidas

