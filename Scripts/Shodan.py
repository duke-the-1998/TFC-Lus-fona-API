import shodan
import json
import csv
from typing import Dict, List, Any
import ipaddress
from datetime import datetime

API_KEY = ''  #Colocar chave da APi de autenticação
api = shodan.Shodan(API_KEY)


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


def consulta_dados(ip: str) -> Any | None:
    """
    Tenta fazer uma coneção a APi do shodan com o ip recebido
    Args:
       ip(str): IP recebido para verificação.
    Returns:
        Any: retorna os dados consultados em caso se sucesso a consulta da api |
        retorna None em caso de falha
    """
    try:
        dados_brutos_api = api.host(ip)
        return dados_brutos_api
    except Exception as e:
        print(f"Erro ao consultar : {e}")
        return


def classificar_dispositivos(banner):
    """
    Classifica os dispovitios atraves de algumas keys predefenidas
    Args:
        banner[str,Any]:  banner que contem a informação para ser procurada
    Returns:
        str: retorna o nome da categoria conectada =True | retorna o string pré-defenida
    """
    keywords = {
        "Câmera de Segurança": ["camera", "dvr", "surveillance", "hikvision", "dahua"],
        "Dispositivo IoT": ["iot", "smart", "device", "router", "switch", "hub"],
        "Infraestrutura Industrial ": ["scada", "modbus", "plc", "siemens", "industrial", "automation"],
        "Servidor": ["http", "ftp", "ssh", "smtp", "database"]
    }
    categoria_detectada = "Outro Dispositivo"
    for categoria, termos in keywords.items():  #itera entre cada categoria das keywornds
        if any(keyword in banner for keyword in termos):  # se algum termo for encontrado coloca o a categoria do mesmo
            categoria_detectada = categoria
            return categoria_detectada
    return categoria_detectada


def acha(ip: str) -> Dict[str, Any]:
    """
    Procura informações sobre o Ip utilizando a API do shodan.

    Args:
        ip (str): Endereço IP para consultar.
    Returns:
        Dict[str, Any]: Dados retornados pelo IP no formato Json.
    """

    dados_brutos_api = consulta_dados(ip)

    if not dados_brutos_api:
        return {"erro": "aconteceu um erro ao consultar o IP."}
    saida = {
        "IP": dados_brutos_api.get("ip_str"),
        "Organizacao": dados_brutos_api.get("org", "Não disponível"),
        "Servicos": [],
        "Certificados_SSL": [],
        "Vulnerabilidades": dados_brutos_api.get("vulns", []),
        "Dominios": dados_brutos_api.get("hostnames", []),
        "Dispositivos_Conectados": []
    }

    for servicos in dados_brutos_api.get("data", []):  #Itera entre todos os  servicos disponivies
        servico = {
            "Porta": servicos.get("port"),
            "Protocolo": servicos.get("transport", "Não disponível"),
            "Modelo": servicos.get("module"),
            "Banner": servicos.get("data", "Não disponível"),
            "Cabeçalhos_HTTP": servicos.get("http", {}).get("headers", {})
        }
        saida["Servicos"].append(servico)

        banner = servicos.get("data", "").lower()
        module = servicos.get("module", "").lower()

        saida["Dispositivos_Conectados"].append({
            "Categoria": classificar_dispositivos(banner),
            "Descrição": module or "Sem descrição",
            "Porta": servicos.get("port")
        })

        # Processar certificados SSL
        ssl = servicos.get("ssl", {})
        if ssl:
            certificado = {
                "CN": ssl.get("cert", {}).get("subject", {}).get("CN", "Não disponível"),
                "Emitente": ssl.get("cert", {}).get("issuer", {}).get("CN", "Não disponível"),
                "Valido_de": converter_data(ssl.get("cert", {}).get("issued", "Data não disponível")),
                "Valido_ate": converter_data(ssl.get("cert", {}).get("expires", "Data não disponível"))
            }
            saida["Certificados_SSL"].append(certificado)

    return saida


def guardar_json(resultados: Dict[str, Any], arquivo: str) -> None:
    """
    Guarda os resultados em formato JSON.

    Args:
        resultados (Dict[str, Any]): Dados que seram guardados.
        arquivo (str): Nome do arquivo JSON.
    """
    try:
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, ensure_ascii=False, indent=4)
        print(f"Resultados guardados no JSON: {arquivo}")
    except Exception as e:
        print(f"Erro ao guardar no JSON: {e}")


def guardar_csv(resultados: Dict[str, Any], arquivo: str) -> None:
    """
    Guarda os resultados em formato CSV.

    Args:
        resultados (Dict[str, Any]): Dados que seram guardados.
        arquivo (str): Nome do arquivo CSV.
    """
    try:
        with open(arquivo, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Escrever cabeçalhos
            writer.writerow(["IP", "Organizacao", "Porta", "Protocolo", "Categoria", "Descrição", "Banner"])

            # Escrever informações dos dispositivos conectados
            for dispositivo in resultados["Dispositivos_Conectados"]:
                for servico in resultados["Servicos"]:
                    writer.writerow([
                        resultados["IP"],
                        resultados["Organizacao"],
                        servico.get("Porta"),
                        servico.get("Protocolo"),
                        dispositivo["Categoria"],
                        dispositivo["Descrição"],
                        servico.get("Banner")
                    ])
        print(f"Resultados guardados no CSV: {arquivo}")
    except Exception as e:
        print(f"Erro ao guardar no CSV: {e}")


def converter_data(asn1_time: str) -> str:
    """
    Converte uma string no formato ASN.1 GeneralizedTime para uma data num formato legível.

    Args:
        asn1_time (str): String no formato 'YYYYMMDDHHMMSSZ'.

    Returns:
        str: Data formatada  num formato mais legível.
    """
    if not asn1_time or asn1_time == "Data não disponível":
        return "Data não disponível"
    try:

        asn1_time = asn1_time.strip()

        dt = datetime.strptime(asn1_time[:-1], "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Formato de data inválido"


def main() -> None:
    """
    Função principal para execução do script.
    """
    while True:
        ip = input("Qual o endereço IP que deseja consultar: ").strip()
        if valida_ip(ip):
            break
        else:
            print("IP invalido!")
    while True:
        output = input("Deseja Guardar os resultados em 1-JSON 2-CSV? Digite o número: \n").strip()
        if output in ["1", "2"]:
            break
        else:
            print("Opção inválida!")

    arquivo = input("Digite o nome do arquivo de saída : ").strip()

    print(f"Consultando os dados do IP {ip}...")
    resultados = acha(ip)

    if output == "1":
        guardar_json(resultados, f"{arquivo}.json")
    elif output == "2":
        guardar_csv(resultados, f"{arquivo}.csv")
    else:
        print("Formato de saída não suportado. Escolha 'json' ou 'csv'.")

    print(json.dumps(resultados, ensure_ascii=False, indent=4))


if __name__ == "__main__":
    main()
