import hashlib

def identify_hash(hash_value):
    length = len(hash_value)

    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    else:
        return "Unknown"


def crack_hash(hash_value, wordlist):
    for word in wordlist:
        word = word.strip()
        hashed_word = hashlib.md5(word.encode()).hexdigest()

        if hashed_word == hash_value:
            return word

    return None


def process_hashes(file_path, wordlist_path):
    results = []

    try:
        with open(file_path, "r") as f:
            hashes = f.readlines()

        with open(wordlist_path, "r") as f:
            wordlist = f.readlines()

        for h in hashes:
            h = h.strip()

            algo = identify_hash(h)
            cracked = crack_hash(h, wordlist)

            results.append({
                "hash": h,
                "algorithm": algo,
                "cracked_password": cracked if cracked else "Not Found"
            })

        return results

    except FileNotFoundError:
        print("[!] Hash file not found.")
        return []