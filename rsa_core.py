import number_theory

def encrpyt(message, PE, mod):
    # (M^e mod n)
    return number_theory.bin_pow(message, PE, mod)

def decrypt(ciphertext, PV, mod):
    # (C^d mod n)
    return number_theory.bin_pow(ciphertext, PV, mod)


