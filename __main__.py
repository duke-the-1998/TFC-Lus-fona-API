#!/usr/bin/env python3

import sys

from delete_sql import delete_tabels
from create_sql import create_tabels
from utils import *

#cabeçalho com variaveis globais
#Anteção ah interface do masscan
masscan_interface = "enp0s3"
#nome da base de dados pode ser mudado
database_name = "monitorizadorIPs.db"


if __name__=="__main__":
    
    #limpa bd, correr apenas da primeira vez ou caso seja necessario limpar a base de dados
    delete_tabels()
    #cria tabelas
    create_tabels()

    # fips = open(sys.argv[1], "r").readlines()
    # run_ips(fips)
    with open(sys.argv[1], "r") as f:#.readlines()
        fdominio = f.readlines()
        run_domains(fdominio)  
    
    #apaga ficheiros auxiliares relativos aos ip's 
    # delete_aux_files()
    
    #f.close()
