#!/usr/bin/env python3

import sys
import argparse
from core.utils import *
from core.create_json import salvar_json, salvar_json_ips
import json
from flask import Flask, jsonify, request



app = Flask(__name__)


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

@app.route('/monitorizador/<type1>/<address>', methods=['GET'])
def run_monitorizador(type1, address):

    print(address)

    if type1 == 'IP':
        run_ips(address, "enp0s3")
        salvar_json_ips()
        return jsonIps

    elif type1 == 'DOM':
        run_domains(address)
        salvar_json()
        return jsonDominios

    else:
        return jsonify({'error': 'Erro na escolha do tipo de scan a fazer'}), 400



if __name__=="__main__":

    app.run(port=5000)
