import json
import csv
from typing import Dict, Any
import ipaddress
import requests

api_key = ''  #Colocar chave da APi de autenticação
tipo = ''
consulta = ''


def valida_ip(ip: str) -> bool:
    """
    Verifica se o endereço IP fornecido é válido.
Args:
    ip (str): IP recebido para verificação.
Returns:
    bool : Retorna true se for um ip quer no formato IPv4 ou IPv6.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def verify_domain(url: str) -> bool:
    """
    Verifica se o domínio ou URL fornecido é válido.

    Args:
       url(str) : dominio recebido para verificação.
    Returns:
        bool: Retorna true se a ligação ao dominio for bem sucedida.

    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        response = requests.get(url, timeout=5)
        print(response.status_code)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def consultar(api_key: str, tipo: str, consulta: str) -> Dict[str, Any] | None:
    """
Consulta a API Leak-Lookup com os parâmetros fornecidos.

Args:
    api_key (str): Chave de autenticação para a API.
    tipo (str): Tipo que vamos consultar dominio, ip, email ou username.
    consulta (str): conteudo que vamos consultar.

Returns:
    Dict[str, Any] | None: Resposta JSON da API  ou None em caso de erro.
"""
    url = 'https://leak-lookup.com/api/search'

    informações = {
        'key': api_key,
        'type': tipo,
        'query': consulta
    }

    try:
        resposta = requests.post(url, data=informações)
        resposta.raise_for_status()
        return resposta.json()

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
        return None


def salvar_json(resultados: list[Dict[str, Any]], arquivo: str) -> None:
    """
 Guarda os resultados no formato JSON no ficheiro com o nome escolhido .

 Args:
     resultados (list[Dict[str, Any]]): Dados que seram guardados.
     arquivo (str): Nome que dará nome ao arquivo.
 """
    try:
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados guardados em JSON {arquivo}")
    except Exception as e:
        print(f"Erro ao guardar  {e}")


def salvar_csv(resultados: list[Dict[str, Any]], arquivo: str, colunas: list[str]) -> None:
    """
 Guarda os resultados no formato CSV no ficheiro com o nome escolhido.

 Args:
     resultados (list[Dict[str, Any]]): Dados a seram  guardados.
     arquivo (str): Nome que dará nome ao  arquivo .
     colunas (list[str]): Lista de nomes das colunas para o CSV.
 """
    try:
        with open(arquivo, 'w', encoding='utf-8', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=colunas)
            writer.writeheader()
            writer.writerows(resultados)
        print(f"Resultados guardados em CSV  {arquivo}")
    except Exception as e:
        print(f"Erro ao guardar  {e}")


def dominio_ip(dados: Dict[str, Any], salvar_jsonoucsv: str, arquivo: str) -> None:
    """
    Processa os dados retornados para consultas de dominio ou ip e guarda os resultados.

    Args:
        dados (Dict[str, Any]): Dados que são retornados pela API.
        salvar_jsonoucsv (str): opção que dita ser será guardado =1 Json ou =2 Csv.

    """
    if not dados['message']:
        print("Nenhum DataLeak encontrado.")
        return

    campos = {
        "email": ["email_address", "emailaddress", "email", "email_address2", "email2"],
        "username": ["username", "uname", "user_name", "member_name"],
        "senha": ["password", "password2", "password3", "password4"]
    }
    resultados = []

    for breach, entradas in dados['message'].items():
        resultado = {"Dataleak": breach}

        emails = []
        usernames = []
        senhas = []

        print(f"\nDataleak: {breach}")

        for entrada in entradas:  # Itera atraves dos das entradas dos dataleaks
            for nome, subnomes in campos.items():  # itera atraves os nomes  dos campos
                for iteracao in subnomes:  # itera entre cada elemento dentro dos nomes
                    if iteracao in entrada:
                        if nome == "email":
                            emails.append(entrada[iteracao])
                        elif nome == "username":
                            usernames.append(entrada[iteracao])
                        elif nome == "senha":
                            senhas.append(entrada[iteracao])

        if emails:
            resultado["Emails"] = emails
            print(f"Emails: {emails}")
        if usernames:
            resultado["Usernames"] = usernames
            print(f"Usernames: {usernames}")
        if senhas:
            resultado["Senhas"] = senhas
            print(f"Senhas: {senhas}")

        resultados.append(resultado)

    print("Resultados finais:", resultados)

    if salvar_jsonoucsv == "1":
        salvar_json(resultados, f"{arquivo}.json")
    elif salvar_jsonoucsv == "2":
        cabecalhos = ["Dataleak", "Emails", "Usernames", "Senhas"]
        salvar_csv(resultados, f"{arquivo}.csv", cabecalhos)


def email_username(dados: Dict[str, Any], salvar_jsonoucsv: str, arquivo: str) -> None:
    """
  Processa os dados retornados para consultar  e-mail ou username e guarda os resultados.

  Args:
      dados (Dict[str, Any]): Dados que são retornados pela API.
        salvar_jsonoucsv (str): opção que dita ser será guardado =1 Json ou =2 Csv.

  """
    resultados = []

    if not dados['message']:
        print("Nenhum DataLeak encontrado.")
        return

    for breach in dados['message']:
        print(f"\nDataleak: {breach}")
        resultados.append({"Dataleak": breach})

    if salvar_jsonoucsv == "1":
        print(resultados)
        salvar_json(resultados, f"{arquivo}.json")

    if salvar_jsonoucsv == "2":
        cabecalhos = ["Dataleak"]
        salvar_csv(resultados, f"{arquivo}.csv", cabecalhos)


def verifica(tipo: str) -> str:
    """
    Verifica se o tipo inserido é valido.
    Args:
        tipo (str): O tipo de dados inserido sendo um domain um ip um user ou email.
    Returns:
        str: retorna o valor do input.
    """
    while True:
        consulta = input(f"Insira o {tipo}: ").strip()
        print(consulta)
        if tipo == "domain" and verify_domain(consulta):
            return consulta
        elif tipo == "ipaddress" and valida_ip(consulta):
            return consulta
        elif tipo == "email_address":
            return consulta
        elif tipo == "username":
            return consulta
        else:
            print(f"{tipo} invalido , Tente novamente.")


def main() -> None:
    """
    Função principal que vai solicitar os parâmetros como a informação a extrair e em que formato quer armazenar,
    realiza a consulta dos mesmos e processa os resultados.
    """
    opcoes = {
        "1": "domain",
        "2": "ipaddress",
        "3": "email_address",
        "4": "username"
    }

    while True:
        opcao = input(
            "Deseja extrair informações sobre um 1-domínio, 2-IP, 3-email ou 4-username? Digite o número: \n").strip()
        if opcao in opcoes:
            tipo = opcoes[opcao]
            consulta = verifica(tipo)
            break
        else:
            print("ERRO: Opção inválida!")

    while True:
        salvar_jsonoucsv = input("Em que formato pretende guardar os resultados em 1-JSON ou 2-CSV? Digite o número: \n").strip()
        if salvar_jsonoucsv in ["1", "2"]:
            break
        else:
            print("ERRO: Opção inválida!")

    arquivo = input("Digite o nome do arquivo de saída: ").strip()

    dados = consultar(api_key, tipo, consulta)

    if tipo in ["domain", "ipaddress"]:
        dominio_ip(dados, salvar_jsonoucsv, arquivo)
    else:
        email_username(dados, salvar_jsonoucsv, arquivo)


if __name__ == "__main__":
    main()
