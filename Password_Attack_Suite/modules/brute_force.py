import time
import itertools
import string


def brute_force_attack(target_password, max_length=4):
    chars = string.ascii_lowercase + string.digits
    attempts = 0
    start_time = time.time()

    print("\n[+] Starting Brute Force Attack...\n")

    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess_password = ''.join(guess)

            if guess_password == target_password:
                end_time = time.time()
                return {
                    "password": target_password,
                    "attempts": attempts,
                    "time": round(end_time - start_time, 2)
                }

    return {
        "password": target_password,
        "attempts": attempts,
        "time": "Not Cracked"
    }