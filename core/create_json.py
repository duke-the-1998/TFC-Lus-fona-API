import json

from core.utils import dic, dicIp


def salvar_json():
    arquivo = "teste.json"
    resultados = dic
    try:
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados salvos em JSON: {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar em JSON: {e}")

def salvar_json_ips():
    arquivo = "testeIp.json"
    resultados = dicIp
    try:
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados salvos em JSON: {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar em JSON: {e}")