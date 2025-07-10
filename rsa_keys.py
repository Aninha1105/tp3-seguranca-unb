import number_theory
import utils

def generate_rsa_key_pair(bits):
    # brief   Gera e salva um par de chaves RSA (pública e privada).
    # param   bits (int) — quantidade de bits de cada primo p e q
    # complexity Esperada: O(bits · k · log n) — depende da geração de primos e do algoritmo de Euclides estendido.

    P = number_theory.gen_prime(bits)
    Q = number_theory.gen_prime(bits)
    N = P * Q
    phi = (P - 1) * (Q - 1)
    e = 65537
    D = number_theory.inverse_mod(e, phi)
    utils.save_public_key("public_key.pem", N, e)
    utils.save_private_key("private_key.pem", N, D)

# generate_rsa_key_pair(1024)