import number_theory

def encrypt(M, PE, mod):
    # brief   Realiza a operação RSA de encriptação: C = M^e mod n
    # param   M (int) — mensagem codificada como inteiro
    # param   PE (int) — expoente público e
    # param   mod (int) — módulo n
    # return  Resultado da encriptação
    # complexity O(log PE)

    return number_theory.bin_pow(M, PE, mod)

def decrypt(C, PV, mod):
    # brief   Realiza a operação RSA de desencriptação: M = C^d mod n
    # param   C (int) — assinatura como inteiro
    # param   PV (int) — expoente privado d
    # param   mod (int) — módulo n
    # return  Resultado da desencriptação
    # complexity O(log PV)

    return number_theory.bin_pow(C, PV, mod)
