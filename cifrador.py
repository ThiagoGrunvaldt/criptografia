import sys
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Configurações de Criptografia ---
# Tamanho do salt (em bytes)
SALT_SIZE = 16
# Tamanho do nonce (IV) do ChaCha20 (12 bytes é o padrão)
NONCE_SIZE = 12
# Tamanho da chave ChaCha20 (32 bytes = 256 bits)
KEY_SIZE = 32
# Iterações do PBKDF2 (quanto maior, mais seguro)
PBKDF2_ITERATIONS = 100_000

# --- Função de Derivação de Chave ---
def derivar_chave(senha: bytes, salt: bytes) -> bytes:
    """Usa PBKDF2 para derivar uma chave segura da senha."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(senha)

# --- Função de Criptografar ---
def criptografar_arquivo(nome_arquivo: str, senha: str):
    """Criptografa o arquivo e salva como _cifrado.txt"""
    try:
        # 1. Ler o arquivo de entrada
        with open(nome_arquivo, 'rb') as f:
            dados_claros = f.read()

        # 2. Gerar salt e nonce (IV) aleatórios
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        # 3. Derivar a chave a partir da senha e do salt
        chave = derivar_chave(senha.encode('utf-8'), salt)

        # 4. Criptografar com ChaCha20-Poly1305
        # MELHORIA: ChaCha20-Poly1305 é um modo "AEAD" (Criptografia Autenticada
        # com Dados Associados). Ele criptografa e gera uma 'tag' de
        # autenticação (Poly1305) que verifica se os dados foram alterados.
        chacha = ChaCha20Poly1305(chave)
        
        # O resultado do encrypt() já contém o ciphertext + tag
        dados_cifrados_com_tag = chacha.encrypt(nonce, dados_claros, None)

        # 5. Montar o nome do arquivo de saída
        base_nome = nome_arquivo.rsplit('.', 1)[0]
        nome_saida = f"{base_nome}_cifrado.txt"

        # 6. Salvar o arquivo de saída
        # O formato será: [SALT] + [NONCE] + [DADOS_CIFRADOS_COM_TAG]
        with open(nome_saida, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(dados_cifrados_com_tag)
            
        print(f"Arquivo '{nome_arquivo}' criptografado com sucesso para '{nome_saida}'")

    except FileNotFoundError:
        print(f"Erro: Arquivo '{nome_arquivo}' não encontrado.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado ao criptografar: {e}")
        sys.exit(1)

# --- Função de Decriptografar ---
def decriptografar_arquivo(nome_arquivo: str, senha: str):
    """Decriptografa o arquivo e salva como _decifrado.txt"""
    try:
        # 1. Ler o arquivo de entrada
        with open(nome_arquivo, 'rb') as f:
            dados_completos = f.read()

        # 2. Extrair os componentes do arquivo
        # [SALT] + [NONCE] + [DADOS_CIFRADOS_COM_TAG]
        salt = dados_completos[:SALT_SIZE]
        nonce = dados_completos[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        dados_cifrados_com_tag = dados_completos[SALT_SIZE + NONCE_SIZE:]

        # 3. Derivar a *mesma* chave usando a senha e o salt extraído
        chave = derivar_chave(senha.encode('utf-8'), salt)

        # 4. Decriptografar e verificar a tag
        chacha = ChaCha20Poly1305(chave)
        
        dados_claros = chacha.decrypt(nonce, dados_cifrados_com_tag, None)

        # 5. Montar o nome do arquivo de saída
        if not nome_arquivo.endswith('_cifrado.txt'):
            print(f"Aviso: O arquivo '{nome_arquivo}' não parece ser um arquivo cifrado.")
            base_nome = nome_arquivo.rsplit('.', 1)[0]
        else:
            base_nome = nome_arquivo.replace('_cifrado.txt', '')
            
        nome_saida = f"{base_nome}_decifrado.txt"

        # 6. Salvar o arquivo de saída
        with open(nome_saida, 'wb') as f:
            f.write(dados_claros)

        print(f"Arquivo '{nome_arquivo}' decriptografado com sucesso para '{nome_saida}'")

    except FileNotFoundError:
        print(f"Erro: Arquivo '{nome_arquivo}' não encontrado.")
        sys.exit(1)
    except InvalidTag:
        # Isso acontece se a senha estiver errada ou o arquivo corrompido!
        print("Erro: SENHA INCORRETA ou arquivo corrompido. Falha na decriptografia.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado ao decriptografar: {e}")
        sys.exit(1)

# --- Função Principal (main) ---
def main():
    # 1. Validar argumentos de entrada
    if len(sys.argv) != 4:
        print("Erro: Uso incorreto.")
        print(f"Exemplo: python {sys.argv[0]} meu_arquivo.txt 'senha123' criptografar")
        print(f"Exemplo: python {sys.argv[0]} meu_arquivo_cifrado.txt 'senha123' decriptografar")
        sys.exit(1) 

    # 2. Atribuir argumentos a variáveis
    nome_arquivo = sys.argv[1]
    senha = sys.argv[2]
    modo = sys.argv[3].lower()

    # 3. Executar a ação correta
    if modo == 'criptografar':
        criptografar_arquivo(nome_arquivo, senha)
    elif modo == 'decriptografar':
        decriptografar_arquivo(nome_arquivo, senha)
    else:
        print(f"Erro: Modo '{modo}' desconhecido. Use 'criptografar' ou 'decriptografar'.")
        sys.exit(1)

# --- Ponto de Entrada do Script ---
if __name__ == "__main__":
    main()