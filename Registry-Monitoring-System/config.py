import winreg

# Multiple registry keys to monitor
REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
]

# Suspicious keywords (basic malware detection)
SUSPICIOUS_KEYWORDS = ["disable", "defender", "malware", "hack", "virus"]