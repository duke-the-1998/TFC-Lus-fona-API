#!/usr/bin/env python3

import sys
import argparse
from core.utils import *
from core.create_json import salvar_json, salvar_json_ips

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
    return parser.parse_args(args)

if __name__=="__main__":
    options = getOptions(sys.argv[1:])

    scan_type = options.type
    iface = options.iface
    input_fname = options.fname

    if scan_type == 'IP':
        with open (input_fname, "r") as f:
            fips = f.read().splitlines()
            run_ips(fips, iface)
            salvar_json_ips()
        delete_aux_files()
    elif scan_type == 'DOM':
        with open(input_fname, "r") as f:
            fdominio = f.read().splitlines()
            run_domains(fdominio)
            salvar_json()
    else:
        print("Tipo de scan incorreto")
