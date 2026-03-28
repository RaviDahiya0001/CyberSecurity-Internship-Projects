import winreg
import json
from config import REGISTRY_PATHS

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

baseline = {}

for key, path in REGISTRY_PATHS:
    baseline[path] = get_registry(key, path)

with open("baseline.json", "w") as f:
    json.dump(baseline, f, indent=4)

print(" Baseline Created Successfully!")