import psutil
import subprocess
import datetime
import time
import os

print("\n==============================")
print(" Windows Process Monitoring Agent ")
print("==============================\n")

# -----------------------------
# LOG FILE
# -----------------------------

log_file = open("monitor_log.txt", "a")

def log(message):

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"

    print(entry)
    log_file.write(entry + "\n")


# -----------------------------
# WHITELIST OF TRUSTED PROCESSES
# -----------------------------

whitelist = {
    "system",
    "system idle process",
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "lsass.exe",
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "powershell.exe",
    "cmd.exe",
    "python.exe",
    "code.exe"
}

# -----------------------------
# SUSPICIOUS PROCESS RELATIONS
# -----------------------------

suspicious_rules = [

    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("chrome.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe")
]

# -----------------------------
# TEMP DIRECTORY KEYWORDS
# -----------------------------

temp_paths = [

    "temp",
    "appdata\\local\\temp",
    "tmp"
]

# -----------------------------
# TRACK PROCESSES
# -----------------------------

seen_processes = set()

log("Monitoring agent started")

# -----------------------------
# REAL TIME MONITOR LOOP
# -----------------------------

while True:

    for proc in psutil.process_iter(['pid','name','ppid','exe']):

        try:

            pid = proc.info['pid']
            name = proc.info['name']
            ppid = proc.info['ppid']
            exe = str(proc.info['exe'])

            if pid not in seen_processes:

                seen_processes.add(pid)

                parent_name = "Unknown"

                try:
                    parent = psutil.Process(ppid)
                    parent_name = parent.name()
                except:
                    pass

                log(f"Process Detected: {name} (PID:{pid})")

                log(f"Parent -> Child : {parent_name} -> {name}")

                # -----------------------------
                # SUSPICIOUS PARENT CHILD CHECK
                # -----------------------------

                for rule in suspicious_rules:

                    if parent_name.lower() == rule[0] and name.lower() == rule[1]:

                        log(f"[ALERT] Suspicious process chain detected: {parent_name} -> {name}")

                # -----------------------------
                # TEMP FOLDER MALWARE CHECK
                # -----------------------------

                if exe != "None":

                    path = exe.lower()

                    for temp in temp_paths:

                        if temp in path:

                            log(f"[WARNING] Process running from TEMP location: {name}")
                            log(f"Path: {path}")

                # -----------------------------
                # UNKNOWN PROCESS CHECK
                # -----------------------------

                if name.lower() not in whitelist:

                    log(f"[INFO] Unknown process detected: {name}")

        except:

            pass


    # -----------------------------
    # WINDOWS SERVICE AUDIT
    # -----------------------------

    try:

        service_data = subprocess.check_output(
            "sc query type= service state= all",
            shell=True
        )

        services = service_data.decode().split("SERVICE_NAME:")

        log("Checking Windows services...")

        for s in services[1:6]:

            lines = s.strip().split("\n")

            service_name = lines[0].strip()

            log(f"Service Found: {service_name}")

    except:

        log("Service monitoring failed")


    # -----------------------------
    # WAIT BEFORE NEXT SCAN
    # -----------------------------

    time.sleep(10)