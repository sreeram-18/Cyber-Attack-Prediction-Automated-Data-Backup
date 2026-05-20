import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

# --- Part A: Process Tracking ---
def monitor_new_processes():
    """Polls for new process executions."""
    print("[*] Starting System Process Tracking...")
    existing_pids = set(psutil.pids())
    
    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - existing_pids
        
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cmdline": " ".join(proc.cmdline())
                }
                # TODO: Send proc_info to your ML anomaly detection queue
                # print(f"[NEW PROCESS] {proc_info['name']} executed.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        existing_pids = current_pids
        time.sleep(0.5) # Sleep to keep CPU usage well under the 5% limit

# --- Part B: File System Monitoring ---
class SensitiveDirectoryHandler(FileSystemEventHandler):
    """Monitors unauthorized file creations or modifications (Ransomware patterns)."""
    def on_modified(self, event):
        if not event.is_directory:
            # print(f"[FILE MODIFIED] {event.src_path}")
            pass

    def on_created(self, event):
        if not event.is_directory:
            file_info = {"action": "created", "path": event.src_path}
            # TODO: Send file_info to ML queue
            # print(f"[FILE CREATED] {event.src_path}")

def start_file_monitoring(path_to_watch):
    print(f"[*] Starting File Integrity Tracking on: {path_to_watch}")
    event_handler = SensitiveDirectoryHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()