import number_theory

def encrypt(M, PE, mod):
    # (M^e mod n)
    return number_theory.bin_pow(M, PE, mod)

def decrypt(C, PV, mod):
    # (C^d mod n)
    return number_theory.bin_pow(C, PV, mod)
