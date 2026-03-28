import time
import hashlib
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import SENSITIVE_FILES, LOG_FILE

# Normalize sensitive file paths
SENSITIVE_FILES = [path.replace("\\", "/").lower() for path in SENSITIVE_FILES]

def normalize_path(path):
    return path.replace("\\", "/").lower()

def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return "ERROR"

def log_event(message):
    print(message)
    # ✅ FIX: encoding added
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"{time.ctime()} - {message}\n")

# ✅ Sensitive check
def is_sensitive(file_path):
    sensitive_extensions = [".pdf", ".docx"]
    return any(file_path.endswith(ext) for ext in sensitive_extensions)

# ✅ Authorization System
TRUSTED_HASHES = {}

def check_authorization(file_path, new_hash):
    if file_path not in TRUSTED_HASHES:
        TRUSTED_HASHES[file_path] = new_hash
        return "FIRST"

    if TRUSTED_HASHES[file_path] == new_hash:
        return "AUTHORIZED"
    else:
        TRUSTED_HASHES[file_path] = new_hash
        return "UNAUTHORIZED"

class MonitorHandler(FileSystemEventHandler):

    def __init__(self):
        self.last_event_time = {}
        self.recent_created = {}
        self.debounce_time = 1
        self.ignore_time = 2

    def is_duplicate(self, file_path, event_type):
        current_time = time.time()
        key = (file_path, event_type)

        if key in self.last_event_time:
            if current_time - self.last_event_time[key] < self.debounce_time:
                return True

        self.last_event_time[key] = current_time
        return False

    def is_recent_create(self, file_path):
        current_time = time.time()
        if file_path in self.recent_created:
            if current_time - self.recent_created[file_path] < self.ignore_time:
                return True
        return False

    def on_created(self, event):
        if not event.is_directory:
            file_path = normalize_path(event.src_path)

            if self.is_duplicate(file_path, "create"):
                return

            self.recent_created[file_path] = time.time()

            if is_sensitive(file_path):
                log_event(f"[ALERT] Sensitive file created: {event.src_path}")
            else:
                log_event(f"[INFO] File created: {event.src_path} (Non-sensitive)")

    def on_modified(self, event):
        if not event.is_directory:
            file_path = normalize_path(event.src_path)

            if self.is_recent_create(file_path):
                return

            if self.is_duplicate(file_path, "modify"):
                return

            hash_value = calculate_hash(event.src_path)

            if is_sensitive(file_path):
                log_event(f"[ALERT] Sensitive file modified: {event.src_path}")

                status = check_authorization(file_path, hash_value)

                if status == "AUTHORIZED":
                    log_event("[AUTHORIZED] No change detected")

                elif status == "UNAUTHORIZED":
                   
                    log_event("[WARNING] Unauthorized modification detected!")

                else:
                    log_event("[INFO] Initial file baseline created")

            else:
                log_event(f"[INFO] File modified: {event.src_path} (Non-sensitive)")

            log_event(f"Generated Hash: {hash_value}")

    def on_deleted(self, event):
        if not event.is_directory:
            file_path = normalize_path(event.src_path)

            if self.is_recent_create(file_path):
                return

            if self.is_duplicate(file_path, "delete"):
                return

            if is_sensitive(file_path):
                log_event(f"[ALERT] Sensitive file deleted: {event.src_path}")
            else:
                log_event(f"[INFO] File deleted: {event.src_path} (Non-sensitive)")

    def on_moved(self, event):
        if not event.is_directory:
            src_path = normalize_path(event.src_path)

            if self.is_duplicate(src_path, "move"):
                return

            log_event(f"[MOVE] {event.src_path} → {event.dest_path}")

if __name__ == "__main__":
    path = "C:/Users/Public"

    if not os.path.exists(path):
        print("Invalid path! Check folder location.")
        exit()

    observer = Observer()
    handler = MonitorHandler()

    observer.schedule(handler, path, recursive=True)
    observer.start()

    print("Monitoring Started on:", path)

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()