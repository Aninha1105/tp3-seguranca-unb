import time, os, hashlib
from number_theory import gen_prime, gcd
from rsa_pss import generate_pss_signature, pss_verify_decrypt_signature, pss_decode
from hasher import calculate_sha3_256_from_bytes

# Configurações
KEY_BITS = 2048
SALT_LEN = hashlib.sha3_256().digest_size
HASH_ALGO = hashlib.sha3_256

# 1. Benchmark de geração de chaves
start = time.time()
P = gen_prime(KEY_BITS // 2)
Q = gen_prime(KEY_BITS // 2)
phi = (P - 1) * (Q - 1)
e = 65537
_, d_raw, _ = gcd(e, phi)
d = d_raw % phi
if d < 0: d += phi
end = time.time()
print(f"Geração de chaves ({KEY_BITS} bits): {end - start:.5f} s")

# 2. Benchmark de assinatura para tamanhos variados
for size in [100_000, 1_000_000, 5_000_000, 10_000_000, 50_000_000, 100_000_000, 500_000_000, 1_000_000_000]:
    data = os.urandom(size)
    start = time.time()
    sig_int, _ = generate_pss_signature(data, d, P*Q, SALT_LEN, HASH_ALGO)
    end = time.time()
    print(f"Assinatura de {size/1e6:.1f} MB: {end - start:.5f} s")

# 3. Benchmark de verificação
    # recupera o hash e decodifica EM
    m_hash = calculate_sha3_256_from_bytes(data)
    em_int = pss_verify_decrypt_signature(sig_int, e, P*Q)
    start = time.time()
    valid = pss_decode(em_int, m_hash, (P*Q).bit_length() - 1, SALT_LEN, HASH_ALGO)
    end = time.time()
    print(f"Verificação de {size/1e6:.1f} MB: {end - start:.5f} s — Válido? {valid}")