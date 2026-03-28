import os
from datetime import datetime

def generate_report(analysis_results, brute_result):
    os.makedirs("output/reports", exist_ok=True)

    file_path = "output/reports/report.txt"

    with open(file_path, "w") as f:
        f.write("=== Password Security Audit Report ===\n\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        # Password Analysis Section
        f.write("---- Password Strength Analysis ----\n\n")

        weak_count = 0

        for r in analysis_results:
            f.write(f"Password: {r['password']}\n")
            f.write(f"Score: {r['score']} | Strength: {r['strength']} | Entropy: {r['entropy']}\n\n")

            if r['strength'] == "Weak":
                weak_count += 1

        f.write(f"\nTotal Weak Passwords: {weak_count}\n\n")

        # Brute Force Section
        f.write("---- Brute Force Simulation ----\n\n")
        f.write(f"Target Password: {brute_result['password']}\n")
        f.write(f"Attempts: {brute_result['attempts']}\n")
        f.write(f"Time Taken: {brute_result['time']} seconds\n\n")

        # Recommendations
        f.write("---- Security Recommendations ----\n\n")
        f.write("- Use strong passwords (min 8 characters)\n")
        f.write("- Include uppercase, lowercase, numbers, and symbols\n")
        f.write("- Avoid common passwords\n")
        f.write("- Use multi-factor authentication\n")

    print(f"[+] Report generated at {file_path}")