#!/usr/bin/env python3

import sys
import argparse

from core.db_utils import create_tabels, delete_tabels
from core.utils import *

#cabeçalho com variaveis globais
# Nome da interface do masscan
INTERFACE = "enp0s3"
# Nome da base de dados pode ser mudado
DATABASE_NAME = "monitorizadorIPs.db"

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Procura informacao sobre dominios ou ips, recebendo como argumentos, uma lista de ips ou uma lista de dominios para pesquisar")
    parser.add_argument("-t", "--type", 
                        help="Tipo de scan a fazer, [IP/DOM]", 
                        type=str,
                        dest='type',
                        required=True)
    parser.add_argument("-f", "--file", 
                        help="Nome do ficheiro de entrada. Ficheiro em que cada linha é um ip ou um dominio",
                        dest='fname',
                        required=True)
    parser.add_argument("-i", "--iface", 
                        help="A interface de rede a ser usada (default: enp0s3)",
                        default="enp0s3",
                        required=False)
    parser.add_argument("-d", "--db_name", 
                        help="O nome do ficheiro da base de dados a ser usado (default: monitorizadorIPs.db)",
                        default="monitorizadorIPs.db",
                        required=False)
    #parser.add_argument("-v", "--verbose",dest='verbose',action='store_true', help="Verbose mode.")
    options = parser.parse_args(args)
    return options

if __name__=="__main__":
    options = getOptions(sys.argv[1:])

    # Nota: Se quiseremos apagar as tabelas podemos apagar o ficheiro ou correr: 
    #delete_tabels(DATABASE_NAME)
    scan_type = options.type
    database_fname = options.db_name
    iface = options.iface
    input_fname = options.fname
    #cria tabelas
    create_tabels(DATABASE_NAME)
    print(options)

    if scan_type == 'IP':
        print(1)
    elif scan_type == 'DOM':
        with open(input_fname, "r") as f: 
            fdominio = f.read().splitlines()
            run_domains(database_fname, fdominio)
    else:
        print("Tipo de scan incorreto")
    
    # fips = open(sys.argv[1], "r").readlines()
    # run_ips(fips)
    #./monito -t IP -f file_ips.txt
    #./monito -t DOM -f file_domains.txt 
    #with open(sys.argv[1], "r") as f:#.readlines()
    #    fdominio = f.read().splitlines()
    #    run_domains(database_fname, fdominio)
    
    #apaga ficheiros auxiliares relativos aos ip's 
    # delete_aux_files()
    
    #f.close()
