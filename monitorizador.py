#!/usr/bin/env python3

import sys

from core.db_utils import create_tabels, delete_tabels
from core.utils import *

#cabeçalho com variaveis globais
# Nome da interface do masscan
INTERFACE = "enp0s3"
# Nome da base de dados pode ser mudado
DATABASE_NAME = "monitorizadorIPs.db"

if __name__=="__main__":
    
    #limpa bd, correr apenas da primeira vez ou caso seja necessario limpar a base de dados
    delete_tabels(DATABASE_NAME)
    #cria tabelas
    create_tabels(DATABASE_NAME)

    # fips = open(sys.argv[1], "r").readlines()
    # run_ips(fips)
    with open(sys.argv[1], "r") as f:#.readlines()
        fdominio = f.read().splitlines()
        run_domains(DATABASE_NAME, fdominio)
    
    #apaga ficheiros auxiliares relativos aos ip's 
    # delete_aux_files()
    
    #f.close()
