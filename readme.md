# Scorpion - Ferramenta de Análise de Segurança Web

Scorpion é um scanner de vulnerabilidades web básico, escrito em Python, projetado para fins educacionais. Ele automatiza a busca por falhas de segurança comuns em aplicações web, como **SQL Injection**, **Cross-Site Scripting (XSS)** e **Directory Traversal**.

---

## ✨ Funcionalidades

-   **Teste de SQL Injection (SQLi)**: Tenta injetar payloads de SQL em campos de formulários para identificar possíveis vulnerabilidades.
-   **Teste de Cross-Site Scripting (XSS)**: Verifica se formulários são vulneráveis a ataques de XSS refletido.
-   **Teste de Directory Traversal**: Tenta acessar arquivos sensíveis no servidor, como `/etc/passwd`.
-   **Análise Concorrente**: Utiliza threads para escanear múltiplos formulários e vulnerabilidades simultaneamente, agilizando o processo.
-   **Saída Colorida**: Apresenta os resultados no terminal com cores para facilitar a identificação da severidade das vulnerabilidades encontradas.

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida para **fins estritamente educacionais e de pesquisa em segurança**. O uso desta ferramenta em sistemas aos quais você não possui autorização explícita é **ilegal**. O autor não se responsabiliza por qualquer dano ou mau uso. Use por sua conta e risco.

---

## ⚙️ Requisitos

-   Python 3.x
-   Bibliotecas: `requests` e `beautifulsoup4`

## 🚀 Instalação

1.  Clone o repositório onde o script está salvo. Se ainda não estiver em um, crie um diretório e salve o script (ex: `scorpion.py`).

2.  Navegue até o diretório do projeto:
    ```bash
    cd /caminho/para/seu/projeto
    ```

3.  Crie um arquivo `requirements.txt` com o seguinte conteúdo:
    ```
    requests
    beautifulsoup4
    ```

4.  Instale as dependências usando o pip:
    ```bash
    pip install -r requirements.txt
    ```

---

## USAGE

Para usar o scanner, execute o script a partir do seu terminal, fornecendo a URL completa (com `http://` ou `https://`) da aplicação que deseja analisar.

### Sintaxe

```bash
python3 scorpion.py <URL> [opções]
