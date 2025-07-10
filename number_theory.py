import secrets
primes = set()

#------------------------------------
# Algoritmo de Euclides Estendido
#------------------------------------
def gcd(a, b):
    # brief   Calcula o MDC (máximo divisor comum) entre a e b, e retorna também os coeficientes de Bézout.
    # param   a (int) — inteiro positivo
    # param   b (int) — inteiro positivo
    # return  (g, x, y) tal que g = gcd(a, b) e ax + by = g
    # complexity O(log(min(a, b))) — tempo logarítmico no pior caso

    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

#------------------------------------
# Exponenciação Modular Binária
#------------------------------------
def bin_pow(base, expo, MOD):
    # brief   Calcula (base^expo) mod MOD de forma eficiente.
    # param   base (int), expo (int), MOD (int)
    # return  resultado de (base^expo) % MOD
    # details Utiliza exponenciação rápida (método quadrado-e-multiplica).
    # complexity O(log expo)

    res = 1
    base %= MOD
    while expo:
        if expo & 1:
            res = (res * base) % MOD
        base = (base * base) % MOD
        expo >>= 1
    return res

#------------------------------------
# Crivo de Eratóstenes (Pré-processamento)
#------------------------------------
def sieve(lim):
    # brief   Gera todos os primos menores que 'lim' e armazena no conjunto global 'primes'.
    # param   lim (int) — limite superior para geração de primos
    # complexity O(n log log n)

    not_prime = set()
    for i in range(2, lim):
        if i not in not_prime:
            primes.add(i)
            for j in range(2 * i, lim, i):
                not_prime.add(j)

#------------------------------------
# Teste auxiliar do Miller-Rabin
#------------------------------------
def composite(n, a, d, s):
    # brief   Verifica se um número é composto usando um witness 'a' no teste de Miller-Rabin.
    # param   n (int), a (int), d (int), s (int)
    # return  True se n é composto, False se possivelmente primo
    # complexity O(s * log n)

    x = bin_pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True

#------------------------------------
# Teste de primalidade probabilístico (Miller-Rabin)
#------------------------------------
def is_prime(n, k):
    # brief   Testa se um número é primo usando Miller-Rabin com k rodadas.
    # param   n (int) — número a ser testado
    # param   k (int) — número de iterações aleatórias (maior k = mais confiável)
    # return  True se n provavelmente é primo, False se composto
    # complexity O(k log n)
    # note     Probabilidade de falso positivo é < 4^{-k}

    if n < 4:
        return n == 2 or n == 3
    if n in primes:
        return True
    for p in primes:
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        if composite(n, a, d, s):
            return False
    return True

#------------------------------------
# Cálculo do Inverso Modular
#------------------------------------
def inverse_mod(a, mod):
    # brief   Calcula o inverso modular de 'a' módulo 'mod'
    # param   a (int), mod (int)
    # return  x tal que (a * x) % mod == 1
    # throws  ValueError se o inverso não existir (a e mod não coprimos)
    # complexity O(log mod)

    g, x, y = gcd(a, mod)
    if g != 1:
        raise ValueError("n são coprimos => n tem inverso")
    return x % mod

#------------------------------------
# Geração de Número Primo com N bits
#------------------------------------
def gen_prime(bits):
    # brief   Gera um número primo com o número exato de bits especificado.
    # param   bits (int) — quantidade de bits desejada para o número primo
    # return  Um número primo de 'bits' bits, gerado aleatoriamente
    # details Gera candidatos ímpares aleatórios até passar no teste de primalidade.
    # complexity O(log bits * k) — onde k=40 é o número de iterações do teste de primalidade

    while True:
        lower_bound = 2 ** (bits - 1)
        upper_bound = 2 ** bits - 1
        candidate = secrets.randbelow(upper_bound - lower_bound + 1) + lower_bound
        if not (candidate & 1):
            candidate += 1
            if candidate > upper_bound:
                continue
        if is_prime(candidate, 40):
            return candidate
sieve(500)