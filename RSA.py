import generator
import number_theory

def rsa_encrpyt():
    pass

def rsa_decrypt():
    pass

p = generator.prime_generator(1024)
q = generator.prime_generator(1024)

n = p * q
phi = (p - 1) * (q - 1)
e = 65537

g, d, x = number_theory.gcd(phi, e)

print(f'phi = {phi} | d = {d}')
print()
print(f'e = {e} | x = {x}')