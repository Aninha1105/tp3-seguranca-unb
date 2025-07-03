import base64

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

def load_public_key(filepath):
    pass

def load_private_key(filepath):
    pass