import requests
import json

def ler_arquivo_linhas(caminho_arquivo):

    linhas=[]
    with open(caminho_arquivo, 'r', encoding='utf-8') as f:

        for linha in f:
            linhas.append(linha.strip())

    return linhas



def teste_api(tipo,arquivo):
    url_base = "http://127.0.0.1:5000/monitorizador"

 
    dicionario= ler_arquivo_linhas(arquivo)


    url = f"{url_base}/{tipo}/"
    headers = {'Content-Type': 'application/json'}



    try:
        resposta = requests.post(url, json=dicionario, headers=headers)

        if resposta.status_code == 200:
            print(json.dumps(resposta.json(), indent=4))
        else:
            print(f"Erro  na API  {resposta.status_code}")
            print(resposta.text)

    except requests.exceptions.RequestException as e:
        print(f"Erro a conectar a api  {e}")

if __name__ == "__main__":
    tipo = "IP"
    arquivo="test.txt"
    teste_api(tipo,arquivo)
