import secrets
primes = []

def gcd(a, b):
    if not b:
        return a, 1, 0

    d, x_, y_ = gcd(b, a % b)
    x = y_
    y = x_ - (a // b) * y_

    return d, x, y

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
            primes.append(i)
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
    return gcd(a, mod)[1]

def gen_prime(bits):
    while True:
        lower_bound = 2 ** (bits - 1)
        upper_bound = 2 ** bits - 1

        candidate = secrets.randbelow(upper_bound - lower_bound + 1) + lower_bound

        if candidate % 2 == 0:
            candidate += 1
            if candidate > upper_bound:
                continue

        if is_prime(candidate, 40):
            return candidate
        
sieve(500)