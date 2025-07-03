import number_theory
import utils

def generate_rsa_key_pair(bits):
    p = number_theory.gen_prime(bits)
    q = number_theory.gen_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = number_theory.inverse_mod(phi, e)
    
    utils.save_public_key("public_key.pem", n, e)
    utils.save_private_key("private_key.pem", n, d)

generate_rsa_key_pair(1024)