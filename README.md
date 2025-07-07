# Sistema de Assinatura Digital RSA-PSS

## Introdução

Este repositório apresenta uma implementação didática do esquema de assinatura digital RSA-PSS (Probabilistic Signature Scheme) em Python, incluindo geração de chaves RSA, assinatura e verificação de mensagens e arquivos. O projeto possui tanto uma interface de linha de comando quanto uma interface gráfica (PyQt6) para facilitar o uso e o aprendizado dos conceitos de criptografia de chave pública.

O projeto está dividido em três partes principais:

- **Parte 1:** Implementação dos algoritmos matemáticos necessários para geração de números primos, operações modulares e geração de chaves RSA.
- **Parte 2:** Implementação do esquema de assinatura digital RSA-PSS, incluindo codificação PSS, geração e formatação de assinaturas.
- **Parte 3:** Verificação de assinaturas RSA-PSS, decodificação e validação conforme o padrão, além de interface gráfica para uso prático.

## Requisitos

- Python 3.7 ou superior
- Biblioteca PyQt6
- Módulos padrão: base64, hashlib, os, sys, struct, json, secrets

## Como executar

Clone o repositório:

```sh
git clone https://github.com/Aninha1105/tp3-seguranca-unb.git
cd tp3-seguranca-unb/
```

Crie e ative um ambiente virtual (opcional, mas recomendado):

No Unix/macOS:
```sh
python3 -m venv venv
source venv/bin/activate
```

No Windows (cmd):
```sh
python -m venv venv
venv\Scripts\activate
```

Instale as dependências:

```sh
pip install -r requirements.txt
```

### Linha de comando

- Para executar o sistema via terminal:

```sh
python main.py
```

Siga o menu interativo para gerar chaves, assinar mensagens/arquivos e verificar assinaturas.

### Interface gráfica

- Para executar a interface gráfica (PyQt6):

```sh
python interface.py
```

Utilize as abas para gerar chaves, assinar e verificar arquivos ou mensagens de forma intuitiva.

## Estrutura dos arquivos

- `main.py`: Interface de linha de comando para todas as operações.
- `interface.py`: Interface gráfica baseada em PyQt6.
- `number_theory.py`: Funções matemáticas para geração de primos e operações modulares.
- `rsa_core.py`: Operações básicas de criptografia RSA.
- `rsa_pss.py`: Implementação do esquema de assinatura digital RSA-PSS.
- `hasher.py`: Funções para cálculo de hash SHA3-256.
- `utils.py`: Utilitários para manipulação de chaves e arquivos.
- `public_key.pem` / `private_key.pem`: Arquivos de chave pública e privada gerados.
- `requirements.txt`: Lista de dependências Python.

## Conclusão

Este repositório serve como material de estudo para compreender o funcionamento interno do RSA, do esquema de assinatura digital PSS e para experimentar a assinatura e verificação de mensagens e arquivos. O projeto implementa todos os passos do RSA-PSS de forma didática, sem uso de bibliotecas externas de criptografia, facilitando o entendimento dos conceitos fundamentais de segurança da informação.