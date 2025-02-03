import requests
import json

def teste_api():
    url_base = "http://127.0.0.1:5000/monitorizador"

    tipo = "IP"
    jsonm = [
        "172.66.43.69",
        "65.21.239.46",
    ]



    url = f"{url_base}/{tipo}/"
    headers = {'Content-Type': 'application/json'}



    try:
        resposta = requests.post(url, json=jsonm, headers=headers)

        if resposta.status_code == 200:
            print(json.dumps(resposta.json(), indent=4))
        else:
            print(f"Erro  na API  {resposta.status_code}")
            print(resposta.text)

    except requests.exceptions.RequestException as e:
        print(f"Erro a conectar a api  {e}")

if __name__ == "__main__":
    teste_api()
