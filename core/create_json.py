# Imports necessários
import json
from core.utils import jsonDominios, jsonIps


def guardar_json():
    """
       Guarda os dados de domínios num ficheiro JSON.

       A função tenta abrir e gravar os dados de domínios, previamente
       recolhidos e armazenados na variável 'jsonDominios', num ficheiro chamado
       'teste.json'. Caso haja algum erro durante o processo, este será tratado
       e apresentado.

       Retorna:
            Retorna um json com os dados dos domínios

       Exceções:
           Caso ocorra algum erro ao tentar guardar o ficheiro, será exibida uma
           mensagem com o detalhe do erro.
       """
    ficheiro = "teste.json"
    resultados = jsonDominios
    try:
        with open(ficheiro, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados guardados em JSON: {ficheiro}")
    except Exception as e:
        print(f"Erro ao guardar em JSON: {e}")


def guardar_json_ips():
    """
       Guarda os dados de ips num ficheiro JSON.

       A função tenta abrir e gravar os dados de ips, previamente
       recolhidos e armazenados na variável 'jsonIps', num ficheiro chamado
       'testeIp.json'. Caso haja algum erro durante o processo, este será tratado
       e apresentado.

       Retorna:
            Retorna um json com os dados dos ips

       Exceções:
           Caso ocorra algum erro ao tentar guardar o ficheiro, será exibida uma
           mensagem com o detalhe do erro.
       """
    ficheiro = "testeIp.json"
    resultados = jsonIps
    try:
        with open(ficheiro, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados guardados em JSON: {ficheiro}")
    except Exception as e:
        print(f"Erro ao guardar em JSON: {e}")
