
import os
import number_theory
import hasher
import rsa_pss
from utils import *

def menu():
    print("\n--- Gerador/Verificador de Assinaturas RSA-PSS ---")
    print("1. Gerar Novo Par de Chaves RSA")
    print("2. Assinar Mensagem ou Arquivo")
    print("3. Verificar Assinatura de Mensagem ou Arquivo")
    print("4. Sair")

keys = load_keys_from_files()
if keys:
    print("Chaves pública e privada carregadas com sucesso.")
    cur_pu, cur_pv = keys["public"], keys["private"]
else:
    print("Nenhuma chave existente encontrada. Por favor, gere novas chaves (opção 1).")
    cur_pu = None
    cur_pv = None

while True:
    menu()
    op = input("Escolha uma opção: ")
    if op == '1':
        print(f"\nGerando um novo par de chaves RSA de {KEY_SIZE_BITS} bits...")
        P = number_theory.gen_prime(KEY_SIZE_BITS // 2)
        Q = number_theory.gen_prime(KEY_SIZE_BITS // 2)
        N = P * Q
        phi = (P - 1) * (Q - 1)
        e = 65537
        _, D, _ = number_theory.gcd(e, phi)
        D %= phi
        if D < 0: D += phi
        cur_pu = {"n": N, "e": e}
        cur_pv = {"n": N, "d": D}
        save_keys_to_files(N, e, D)
        clear()

    elif op == '2':
        if not cur_pv:
            print("Erro: Nenhuma chave privada carregada. Por favor, gere chaves primeiro (opção 1).")
            continue
        print("\n--- Assinar ---")
        s_type = input("Assinar (M)ensagem de texto ou (A)rquivo? (M/A): ").upper()
        msg_bytes_to_sign = None

        if s_type == 'M':
            msg = input("Digite a mensagem a ser assinada: ").strip()
            msg_bytes_to_sign = msg.encode('utf-8')
            out = "assinatura_mensagem.sig"
        elif s_type == 'A':
            arq = input("Digite o caminho do arquivo a ser assinado (e.g., documento.txt): ")
            if not os.path.exists(arq):
                print("Erro: Arquivo não encontrado.")
                continue
            try:
                with open(arq, 'rb') as f:
                    msg_bytes_to_sign = f.read()
                out = os.path.basename(arq) + ".sig"
            except Exception as e:
                print(f"Erro ao ler o arquivo: {e}")
                continue
        else:
            print("Opção inválida.")
            continue

        if msg_bytes_to_sign is not None:
            try:
                signature_int, _ = rsa_pss.generate_pss_signature(msg_bytes_to_sign, cur_pv["d"], cur_pv["n"], DEFAULT_SALT_LEN,HASH_ALGO)
                formatted_signature_str = rsa_pss.format_pss_signature_for_storage(signature_int, cur_pv["n"], DEFAULT_SALT_LEN, HASH_ALGO_NAME)
                with open(out, "w") as f:
                    f.write(formatted_signature_str)
                print(f"Assinatura gerada e salva em '{out}'.")
                clear()
            except Exception as e:
                print(f"Erro ao gerar assinatura: {e}")

    elif op == '3':
        if not cur_pu:
            print("Erro: Nenhuma chave pública carregada. Por favor, gere chaves primeiro (opção 1).")
            continue
        print("\n--- Verificar ---")
        sig_path = input("Digite o caminho do arquivo de assinatura (.sig): ")
        if not os.path.exists(sig_path):
            print("Erro: Arquivo de assinatura não encontrado.")
            continue
        try:
            with open(sig_path, "r") as f:
                formatted_signature_str = f.read()
            parsed_sig = rsa_pss.parse_pss_signature_from_storage(formatted_signature_str)
        except Exception as e:
            print(f"Erro ao ler ou parsear o arquivo de assinatura: {e}")
            continue
        
        og_msg_hash = None
        t = input("Verificar (M)ensagem de texto ou (A)rquivo? (M/A): ").upper()

        if t == 'M':
            msg = input("Digite a mensagem original para verificação: ").strip()
            og_msg_bytes = msg.encode('utf-8')
            og_msg_hash = hasher.calculate_sha3_256_from_bytes(og_msg_bytes)

        elif t == 'A':
            arq = input("Digite o caminho do arquivo original para verificação (e.g., documento.txt): ")
            if not os.path.exists(arq):
                print("Erro: Arquivo original não encontrado.")
                continue
            try:
                og_msg_hash = hasher.calculate_sha3_256_from_file(arq)
            except Exception as e:
                print(f"Erro ao ler ou hashear o arquivo original: {e}")
                continue
        else:
            print("Opção inválida.")
            clear()
            continue
        
        if og_msg_hash is not None:
            try:
                # recuperar EM da assinatura
                em_int = rsa_pss.pss_verify_decrypt_signature(parsed_sig["signature_int"], cur_pu["e"],cur_pu["n"])
                
                # decodifica e compara com o hash do conteúdo original
                ok = rsa_pss.pss_decode(em_int, og_msg_hash, cur_pu["n"].bit_length() - 1, parsed_sig["salt_length"], HASH_ALGO)

                if ok:
                    print("\n>>> VERIFICAÇÃO BEM-SUCEDIDA: A assinatura é VÁLIDA! <<<")
                else:
                    print("\n>>> VERIFICAÇÃO FALHOU: A assinatura é INVÁLIDA! <<<")
                clear()
            except Exception as e:
                print(f"Erro durante o processo de verificação: {e}")

    elif op == '4':
        print("Saindo do programa. Adeus!")
        break
    else:
        print("Opção inválida. Por favor, escolha um número de 1 a 4.")
        clear()
    

