import winreg
import json
import time
import datetime
from config import REGISTRY_PATHS, SUSPICIOUS_KEYWORDS

IGNORE_ENTRIES = [
    "OneDrive",
    "SecurityHealth",
    "RtkAudUService",
    "HPSEU_Host_Launcher"
]

def get_registry(key, path):
    data = {}
    try:
        reg = winreg.OpenKey(key, path)
        i = 0
        while True:
            name, value, _ = winreg.EnumValue(reg, i)
            data[name] = value
            i += 1
    except:
        pass
    return data

with open("baseline.json") as f:
    baseline = json.load(f)

# temp memory for delete confirmation
delete_buffer = {}

while True:
    for key, path in REGISTRY_PATHS:
        current = get_registry(key, path)

        if path not in baseline:
            baseline[path] = {}

        # NEW or MODIFIED entries
        for entry in current:
            if entry in IGNORE_ENTRIES:
                continue

            if entry not in baseline[path]:
                print(f"🚨 New Entry: {entry}")

                for word in SUSPICIOUS_KEYWORDS:
                    if word in entry.lower():
                        print("⚠️ Possible Malware Detected!")

                baseline[path][entry] = current[entry]

            # VALUE CHANGE detection
            elif baseline[path][entry] != current[entry]:
                print(f"⚠️ Modified Entry: {entry}")
                baseline[path][entry] = current[entry]

        # DELETE detection (with delay)
        for entry in list(baseline[path].keys()):
            if entry in IGNORE_ENTRIES:
                continue

            if entry not in current:
                if entry not in delete_buffer:
                    delete_buffer[entry] = time.time()
                else:
                    # confirm delete after 15 sec
                    if time.time() - delete_buffer[entry] > 15:
                        print(f"⚠️ Confirmed Deleted: {entry}")
                        del baseline[path][entry]
                        del delete_buffer[entry]
            else:
                # still exists → remove from buffer
                if entry in delete_buffer:
                    del delete_buffer[entry]

    time.sleep(10)