import hashlib

# parte 2 - item a
def calculate_sha3_256_from_file(arq):
    sha3_hash = hashlib.sha3_256()
    try:
        with open(arq, "rb") as f:
            while True:
                b_block = f.read(4096)
                if not b_block:
                    break
                sha3_hash.update(b_block)
        return sha3_hash.digest()
    except FileNotFoundError:
        print(f"arquivo '{arq}' não foi encontrado.")
        raise
    except Exception as e:
        print(f"erro ao ler o arquivo: {e}")
        raise

def calculate_sha3_256_from_bytes(msg_bytes):
    sha3_hash = hashlib.sha3_256()
    sha3_hash.update(msg_bytes)
    return sha3_hash.digest()

