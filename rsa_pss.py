import hashlib
import struct
import os
import json
import base64
import hasher
import rsa_core

# parte 2 - item b
# RFC pag 67
def mgf1(seed, mask_len, hash_algo=hashlib.sha3_256):
    # brief   Implementa a função de geração de máscara MGF1 conforme RFC 8017 (p.67).
    # param   seed (bytes) — semente para gerar a máscara
    # param   mask_len (int) — tamanho da máscara desejada em bytes
    # param   hash_algo — função hash (por padrão SHA3-256)
    # return  Máscara pseudoaleatória de comprimento mask_len
    # complexity O(mask_len / h_len)

    h_len = hash_algo().digest_size
    t = b""

    for i in range((mask_len + h_len - 1) // h_len):
        c = struct.pack(">I", i)  
        HS = hash_algo()
        HS.update(seed)
        HS.update(c)
        t += HS.digest()
        
    return t[:mask_len]

# parte 2 - item b
# RFC pag 42 (9.1.1)
def pss_encode(message_hash_bytes, em_bits, salt_len, hash_algo=hashlib.sha3_256, specific_salt=None):
    # brief   Codifica uma mensagem com o esquema EMSA-PSS.
    # param   message_hash_bytes (bytes) — digest da mensagem original
    # param   em_bits (int) — número de bits do bloco codificado EM
    # param   salt_len (int) — comprimento do salt (em bytes)
    # return  em (int), salt (bytes) — bloco codificado como inteiro e o salt usado
    # complexity O(mask_len / h_len + hash)

    h_len = hash_algo().digest_size
    em_len = (em_bits + 7) // 8

    if em_len < h_len + salt_len + 2:
        raise ValueError("comprimento da mensagem codificada EM é muito pequeno para PSS.")

    # random string de octeto (
    # steps from RFC p43
    salt = os.urandom(salt_len) if specific_salt is None else specific_salt
    
    # m’ = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    m_prime = b'\x00' * 8 + message_hash_bytes + salt

    # H = Hash(M’)    
    h_prime_hasher = hash_algo()
    h_prime_hasher.update(m_prime)
    h_prime = h_prime_hasher.digest()

    ps_len = em_len - salt_len - h_len - 2
    # db = PS || 0x01 || salt
    db = b'\x00' * ps_len + b'\x01' + salt

    # dbmask = mgf1(h', emLen - hLen - 1)
    db_mask = mgf1(h_prime, em_len - h_len - 1, hash_algo)

    # maskeddb = DB \xor dbMask
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    # "Set the leftmost 8emLen - emBits bits of the leftmost octet
    # in maskedDB to zero".
    nz = 8 * em_len - em_bits
    if nz:
        aux_msk = (1<<(8-nz))-1
        masked_db = bytes([masked_db[0] & aux_msk]) + masked_db[1:]

    # em = maskedDB || H' || 0xbc
    em = masked_db + h_prime + b'\xbc'

    #em e salt utilizado
    return int.from_bytes(em, byteorder='big'), salt

# parte 2 - item c
# RFC pag 37
def generate_pss_signature(msg_bytes_original, D, MOD, salt_len=32, hash_algo=hashlib.sha3_256, specific_salt=None):
    # brief   Gera uma assinatura digital RSA-PSS para uma mensagem em bytes.
    # param   msg_bytes_original (bytes) — mensagem original
    # param   D (int) — expoente privado
    # param   MOD (int) — módulo RSA
    # return  (signature_int, salt) — assinatura como inteiro e salt usado
    # complexity O(log D + hash + MGF1)

    M = hasher.calculate_sha3_256_from_bytes(msg_bytes_original)
    
    # "EM of length \ceil ((modBits - 1)/8) octets such that the bit
    # length of the integer OS2IP (EM) is at most
    # modBits - 1, where modBits is the length in bits of the RSA
    # modulus n"
    MOD_BITS = MOD.bit_length() - 1
    em_int, gen_salt = pss_encode(M, MOD_BITS, salt_len, hash_algo, specific_salt=specific_salt)
    
    # assinando EM 
    sig_int = rsa_core.decrypt(em_int, D, MOD)
    
    return sig_int, gen_salt

######################
# parte 2 - item d
def format_pss_signature_for_storage(sig_int, MOD, salt_len, hash_algo_name="sha3_256"):
    # brief   Formata a assinatura e metadados para armazenamento (em Base64).
    # param   sig_int (int), MOD (int), salt_len (int), hash_algo_name (str)
    # return  Assinatura codificada como string Base64 (ES)
    # complexity O(n) — depende do tamanho da assinatura

    sig_len = (MOD.bit_length() + 7) // 8
    sig_bytes = sig_int.to_bytes(sig_len, byteorder='big')
    sig_data = {
        "signature": base64.b64encode(sig_bytes).decode('utf-8'),
        "salt_length": salt_len,
        "hash_algorithm": hash_algo_name,
    }
    json_data = json.dumps(sig_data)
    ES = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')
    return ES

# parte 3 - item a    
def parse_pss_signature_from_storage(ES):
    # brief   Recupera os dados da assinatura a partir da string Base64 armazenada.
    # param   ES (str) — string codificada da assinatura
    # return  Dicionário com: signature_int, salt_length, hash_algorithm_name
    # complexity O(n) — depende do tamanho da codificação Base64

    decoded_json_bytes = base64.b64decode(ES)
    decoded_json_str = decoded_json_bytes.decode('utf-8')
    sig_data = json.loads(decoded_json_str)
    sig_b64 = sig_data.get("signature")
    salt_length = sig_data.get("salt_length")
    H_algo = sig_data.get("hash_algorithm")
    if sig_b64 is None or salt_length is None or H_algo is None:
        raise ValueError("Dados essenciais da assinatura ausentes na estrutura JSON.")
    sig_bytes = base64.b64decode(sig_b64)
    sig_int = int.from_bytes(sig_bytes, byteorder='big')
    return {
        "signature_int": sig_int,
        "salt_length": salt_length,
        "hash_algorithm_name": H_algo
    }
######################

# parte 3 - item b
# RFC pag 44 (9.1.2)
# Verification
def pss_decode(em_int, m_hash_bytes_expected, em_bits, salt_len, hash_algo=hashlib.sha3_256):
    # brief   Verifica a validade do bloco codificado EM de acordo com PSS.
    # param   em_int (int), m_hash_bytes_expected (bytes), em_bits (int), salt_len (int)
    # return  True se o bloco EM é válido, False se inválido
    # complexity O(mask_len / h_len + hash)

    h_len = hash_algo().digest_size
    em_len = (em_bits + 7) // 8
    try:
        em_bytes = em_int.to_bytes(em_len, byteorder='big')
    except OverflowError:
        print("erro: EM (int) maior que o esperado em bytes.")
        return False
    
    # "If the e rightmost octet of EM does not have hexadecimal value
    # 0xbc, output "inconsistent" and stop."
    if em_bytes[-1] != 0xbc:
        print("erro: Último byte não é 0xbc.")
        return False
    
    # inconsistent len
    if em_len < h_len + salt_len + 2:
        return False

    masked_db = em_bytes[:em_len - h_len - 1]
    h_prime = em_bytes[em_len - h_len - 1: em_len - 1]

    # leftmost 8emLen - emBits -> 0
    nz = 8 * em_len - em_bits
    if nz > 0:
        msb_mask = ((1<<nz)-1)<<(8-nz)
        if (masked_db[0] & msb_mask):
            print("erro: Bits não utilizados do primeiro byte não são zero.")
            return False
    
    # dbMask = MGF(H, emLen - hLen - 1).
    db_mask = mgf1(h_prime, em_len - h_len - 1, hash_algo)
    # maskedDB \xor dbMask.
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    #  "Set the leftmost 8emLen - emBits bits of the leftmost octet
    # in maskedDB to zero".
    if nz:
        db_msb_mask = (1 << (8 - nz)) - 1
        db = bytes([db[0] & db_msb_mask]) + db[1:]

    ps_len = em_len - salt_len - h_len - 2
    ok_pad = all(b == 0x00 for b in db[:ps_len])
    if not ok_pad or db[ps_len] != 0x01:
        print("erro: Padding (PS) ou separador 0x01 inválido.")
        return False

    # salt = last sLen octets of db
    sal_rec = db[ps_len + 1:]
    
    # M’ = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    m_prime_rec = b'\x00' * 8 + m_hash_bytes_expected + sal_rec
    # H’ = Hash(M’)
    h_prime_rec_HS = hash_algo()
    h_prime_rec_HS.update(m_prime_rec)
    h_prime_rec = h_prime_rec_HS.digest()

    # H = H' ?
    return h_prime == h_prime_rec

# parte 3 - item c
# RFC pag 35
def pss_verify_decrypt_signature(sig_int, e, MOD):
    # brief   Decifra a assinatura digital RSA usando a chave pública.
    # param   sig_int (int) — assinatura como inteiro
    # param   e (int) — expoente público
    # param   MOD (int) — módulo RSA
    # return  Valor decifrado (bloco EM codificado)
    # complexity O(log e)

    return rsa_core.encrypt(sig_int, e, MOD)
