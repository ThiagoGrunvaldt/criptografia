# Trabalho de Sistema de Segurança: Criptografia
Este projeto é um script de linha de comando em Python para criptografar e descriptografar arquivos de texto.
O algoritmo de criptografia ChaCha20-Poly1305 é utilizado, em conjunto com a função de derivação de chaves PBKDF2, para gerar uma chave segura a partir de uma senha fornecida pelo usuário.

## Requisitos
- Python 3.x  
- Biblioteca cryptography  
- Windows  
python -m pip install cryptography  
- Linux  
pip3 install cryptography

## Modo de Uso
python cifrador.py [arquivo] [chave] [modo]  
### Argumentos
[arquivo] O nome do arquivo de entrada (ex: teste.txt ou teste_cifrado.txt ou "arquivo de teste.txt").  
[chave]: A senha para criptografar ou descriptografar.  
[modo]: A operação a ser realizada. Deve ser 'criptografar' ou 'decriptografar'.