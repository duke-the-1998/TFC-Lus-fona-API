import requests
import json
from typing import Dict, Any


def consultar_cv(cve_id):
    """
    Consulta informações sobre uma  determinada CVE na API do NVD.

    Args:
        cve_id (str): ID do CVE.

    Returns:
        list[Dict[str, Any]]: Lista das vulnerabilidades encontradas ou Nada em caso de erro.
    """
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'

    params = {
        'cveId': cve_id
    }

    try:  # Tenta estabelecer ligação com a Api via url em caso de falha da print do Erro.
        resposta = requests.get(url, params=params)
        resposta.raise_for_status()
        resposta = resposta.json()
        return resposta.get('vulnerabilities', [])
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
        return


def guardar_json(resultados: list[Dict[str, Any]], arquivo: str) -> None:
    """
    Guarda os resultados da pesquisa com a  informação de uma  CVE no formato JSON.

    Args:
        resultados (list[Dict[str, Any]]): Dados a serem guardados.
        arquivo (str): Nome do arquivo.
    """
    try:  # Tenta guardar o arquivo via json se nao conseguir da print no Erro.
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados guardados em JSON: {arquivo}")
    except Exception as e:
        print(f"Erro ao guardar: {e}")


def main() -> None:
    """
    Obtem informações de uma   CVE e guarda as mesmas num arquivo JSON.
    """
    cve = input('Insira o CVE no modelo "CVE-2019-1010218": ').strip()
    resultados = consultar_cv(cve)

    if resultados:
        guardar_json(resultados, "resultado.json")
        print(json.dumps(resultados, ensure_ascii=False, indent=4))
    else:
        print("Nenhum dado encontrado.")


if __name__ == '__main__':
    main()
