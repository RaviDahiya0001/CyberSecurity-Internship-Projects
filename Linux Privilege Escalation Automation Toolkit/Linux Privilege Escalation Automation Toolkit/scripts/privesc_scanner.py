#!/usr/bin/env python3
import os

print("===================================")
print(" Linux Privilege Escalation Scanner ")
print("===================================\n")

print("[+] System Information")
os.system("whoami")
os.system("id")
os.system("uname -a")
os.system("cat /etc/os-release")
print("\n[+] Scanning for SUID/SGID Binaries")
os.system("find / -perm -4000 -type f 2>/dev/null")
print("\n[+] Scanning for World-Writable Files")
os.system("find / -writable -type f 2>/dev/null")

print("\n[+] Scanning for World-Writable Directories")
os.system("find / -writable -type d 2>/dev/null")
print("\n[+] Sudo Privileges Enumeration")
os.system("sudo -l")
print("\n[+] Cron Job Enumeration")
os.system("crontab -l")
os.system("ls -la /etc/cron*")
print("\n[+] Kernel Version Information")
os.system("uname -r")
os.system("uname -a")

print("\n[!] Advisory: Outdated kernels may contain known privilege escalation vulnerabilities (CVEs).")
