import number_theory
import secrets

def prime_generator(bits):

    while True:
        lower_bound = 2 ** (bits - 1)
        upper_bound = 2 ** bits - 1

        candidate = secrets.randbelow(upper_bound - lower_bound + 1) + lower_bound

        if candidate % 2 == 0:
            candidate += 1
            if candidate > upper_bound:
                continue

        if number_theory.is_prime(candidate, 40):
            return candidate
    
number_theory.sieve(500)