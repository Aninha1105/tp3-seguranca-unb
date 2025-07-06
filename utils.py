import base64
import os
import hashlib

KEY_SIZE_BITS = 2048 
DEFAULT_SALT_LEN = 32 # salt = h_len SHA-3-256
HASH_ALGO = hashlib.sha3_256 
HASH_ALGO_NAME = "sha3_256" 
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

def clear():
    input("\nPressione ENTER para continuar...")
    os.system('cls' if os.name == 'nt' else 'clear')

def encode_b64(N, X):
    PX = f"{N},{X}"
    PX_bytes = PX.encode('utf-8')
    PX_b64 = base64.b64encode(PX_bytes).decode('utf-8')
    return PX_b64

def save_file(filename, content):
    with open(filename, "w") as f:
        f.write(content)

def save_public_key(filepath, n, e):
    PU_b64 = encode_b64(n, e)
    PU_pem = f"-----BEGIN PUBLIC KEY-----\n{PU_b64}\n-----END PUBLIC KEY-----"
    save_file(filepath, PU_pem)
    
def save_private_key(filepath, n, d):
    PV_b64 = encode_b64(n, d)
    PV_pem = f"-----BEGIN PRIVATE KEY-----\n{PV_b64}\n-----END PRIVATE KEY-----"
    save_file(filepath, PV_pem)

def _decode_custom_b64_key(pem_content: str) -> tuple[int, int]:
    # decodifica pem costumizado
    # remove cabeçalhos/rodapés PEM e quebras de linha
    b64_data = pem_content.replace(f"-----BEGIN PUBLIC KEY-----", "") \
                          .replace(f"-----END PUBLIC KEY-----", "") \
                          .replace(f"-----BEGIN PRIVATE KEY-----", "") \
                          .replace(f"-----END PRIVATE KEY-----", "") \
                          .replace("\n", "")
    decoded_bytes = base64.b64decode(b64_data)
    decoded_str = decoded_bytes.decode('utf-8')
    n_str, x_str = decoded_str.split(',')
    return int(n_str), int(x_str)

def load_public_key(filepath: str) -> dict:
    try:
        with open(filepath, "r") as f:
            pub_pem = f.read()
        n, e = _decode_custom_b64_key(pub_pem)
        return {"n": n, "e": e}
    except FileNotFoundError:
        print(f"erro: Arquivo de chave pública '{filepath}' não encontrado.")
        return None
    except Exception as e:
        print(f"erro ao carregar chave pública de '{filepath}': {e}")
        return None

def load_private_key(filepath: str) -> dict:
    try:
        with open(filepath, "r") as f:
            priv_pem = f.read()
        n, d = _decode_custom_b64_key(priv_pem)
        return {"n": n, "d": d}
    except FileNotFoundError:
        print(f"erro: Arquivo de chave privada '{filepath}' não encontrado.")
        return None
    except Exception as e:
        print(f"erro ao carregar chave privada de '{filepath}': {e}")
        return None

def load_keys_from_files():
    PU_data = load_public_key(PUBLIC_KEY_FILE)
    PV_data = load_private_key(PRIVATE_KEY_FILE)
    if PU_data and PV_data:
        return { "public": PU_data, "private": PV_data }
    return None

def save_keys_to_files(n, e, d):
    try:
        save_public_key(PUBLIC_KEY_FILE, n, e)
        save_private_key(PRIVATE_KEY_FILE, n, d)
        print(f"chaves salvas com sucesso em {PUBLIC_KEY_FILE} e {PRIVATE_KEY_FILE}.")
    except Exception as e:
        print(f"erro ao salvar chaves: {e}")