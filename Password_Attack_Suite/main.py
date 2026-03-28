from modules.dictionary_generator import generate_dictionary, save_wordlist
from modules.password_analyzer import analyze_wordlist
from modules.brute_force import brute_force_attack
from modules.report_generator import generate_report
from modules.hash_module import process_hashes

def main():
    print("\n=== Password Cracking & Credential Attack Suite ===\n")

    name = input("Enter target name: ")
    dob = input("Enter DOB (ddmmyyyy): ")

    # Dictionary Generation
    wordlist = generate_dictionary(name, dob)
    save_wordlist(wordlist)

    print("\n[✔] Dictionary Generated Successfully\n")

    # Password Analysis
    analysis_results = analyze_wordlist("data/wordlists/wordlist.txt")

    print("\n--- Password Strength Analysis ---\n")
    for r in analysis_results:
        print(f"{r['password']} | Score: {r['score']} | {r['strength']} | Entropy: {r['entropy']}")

    # Hash Cracking (NEW 🔥)
    print("\n--- Hash Cracking Module ---\n")
    hash_results = process_hashes(
        "data/hashes/sample_hashes.txt",
        "data/wordlists/wordlist.txt"
    )

    for h in hash_results:
        print(f"Hash: {h['hash']} | Algo: {h['algorithm']} | Cracked: {h['cracked_password']}")

    # Brute Force Simulation
    target = input("\nEnter password to simulate brute-force attack: ")
    brute_result = brute_force_attack(target)

    print("\n--- Brute Force Result ---\n")
    print(f"Password: {brute_result['password']}")
    print(f"Attempts: {brute_result['attempts']}")
    print(f"Time Taken: {brute_result['time']} seconds")

    # Generate Report
    generate_report(analysis_results, brute_result)

if __name__ == "__main__":
    main()