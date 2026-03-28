import re
import math

def calculate_entropy(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[@#$%^&*!]", password):
        charset += 10

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)


def check_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[@#$%^&*!]", password):
        score += 1

    entropy = calculate_entropy(password)

    if score <= 2:
        strength = "Weak"
    elif score == 3 or score == 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return score, strength, entropy


def analyze_wordlist(file_path):
    results = []

    try:
        with open(file_path, "r") as f:
            passwords = f.readlines()

        for pwd in passwords:
            pwd = pwd.strip()
            score, strength, entropy = check_strength(pwd)

            results.append({
                "password": pwd,
                "score": score,
                "strength": strength,
                "entropy": entropy
            })

        return results

    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return []