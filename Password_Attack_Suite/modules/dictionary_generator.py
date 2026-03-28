import os

def generate_dictionary(name, dob):
    wordlist = []

    # Basic patterns
    wordlist.append(name)
    wordlist.append(name + "123")
    wordlist.append(name + dob)
    wordlist.append(name.capitalize() + "@123")

    # DOB variations
    wordlist.append(dob)
    wordlist.append(dob + "123")

    # Common passwords
    common = ["password", "admin", "123456", "welcome"]
    wordlist.extend(common)

    return list(set(wordlist))  # remove duplicates


def save_wordlist(wordlist):
    os.makedirs("data/wordlists", exist_ok=True)

    file_path = "data/wordlists/wordlist.txt"

    with open(file_path, "w") as f:
        for word in wordlist:
            f.write(word + "\n")

    print(f"[+] Wordlist saved at {file_path}")