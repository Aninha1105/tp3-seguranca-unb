import secrets
primes = set()

def gcd(a, b):
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def bin_pow(base, expo, MOD):
    res = 1
    base %= MOD
    while expo:
        if expo & 1:
            res = (res * base) % MOD
        base = (base * base) % MOD
        expo >>= 1
    return res

def sieve(lim):
    not_prime = set()
    for i in range(2, lim):
        if i not in not_prime:
            primes.add(i)
            for j in range(2 * i, lim, i):
                not_prime.add(j)
    
def composite(n, a, d, s):
    x = bin_pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True

def is_prime(n, k):
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

def inverse_mod(a, mod):
    g, x, y = gcd(a, mod)
    if g != 1:
        raise ValueError("n sao coprimos => n tem inverso")
    return x % mod

def gen_prime(bits):
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