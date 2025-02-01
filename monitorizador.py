#!/usr/bin/env python3


# Imports necessários
from core.utils import *
from core.create_json import guardar_json, guardar_json_ips
from flask import Flask, jsonify, request
import json

# Cria uma instância da aplicação Flask
app = Flask(__name__)


@app.route('/monitorizador/<typeScan>/<address>/', methods=['POST'])
def run_monitorizador(typeScan, address):
    """
    Rota para monitorização de IPs ou domínios.

    Dependendo do tipo de scan solicitado, esta função executa a recolha de
    informações sobre IPs ou domínios e retorna os dados no formato JSON.

    Parâmetros:
        typeScan (str): Tipo de scan. Pode ser 'IP' para+ IPs ou 'DOM' para domínios.
        address (str): Endereço do IP ou domínio a ser monitorizado.

    Retorna:
        Flask Response: Um objeto JSON contendo as informações de IPs ou domínios
    """

    if request.method == 'POST':
        data = request.json

        if typeScan == 'IP':
            run_ips(address)
            guardar_json_ips()
            return jsonIps

        elif typeScan == 'DOM':
            run_domains(data)
            guardar_json()
            return jsonDominios

        else:
            return jsonify({'error': 'Erro na escolha do tipo de scan a fazer'}), 400
    else:
        return jsonify({'error': 'Método não permitido'}), 405





if __name__ == "__main__":
    # Executa a aplicação Flask na porta 5000
    app.run(port=5000)
