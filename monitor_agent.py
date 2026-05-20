import threading
import time
import psutil
from scapy.all import sniff, IP, TCP, UDP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# =====================================================================
# 1. PACKET SNIFFING CONFIGURATION & LOGIC
# =====================================================================
def process_packet(packet):
    """Callback function to process each packet on the fly with low overhead."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        src_port, dst_port = None, None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        packet_metadata = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": len(packet)
        }
        
        # Printing for verification (Comment this out later to save CPU)
        print(f"[NET TRAFFIC] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {proto}")

def start_network_sniffing(interface=None):
    """Starts packet sniffing in a non-blocking background thread."""
    print("[*] Starting Real-Time Packet Sniffing...")
    # store=0 ensures packets are dropped from RAM immediately to stay under 100MB
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={"iface": interface, "prn": process_packet, "store": 0}, 
        daemon=True
    )
    sniff_thread.start()


# =====================================================================
# 2. SYSTEM PROCESS TRACKING LOGIC
# =====================================================================
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
                print(f"[NEW PROCESS] PID {pid}: {proc_info['name']} executed.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        existing_pids = current_pids
        time.sleep(0.5) # Crucial sleep to keep CPU usage well under 5%


# =====================================================================
# 3. FILE SYSTEM INTEGRITY MONITORING LOGIC
# =====================================================================
class SensitiveDirectoryHandler(FileSystemEventHandler):
    """Monitors unauthorized file creations or modifications."""
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[FILE MODIFIED] {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            print(f"[FILE CREATED] {event.src_path}")

def start_file_monitoring(path_to_watch):
    print(f"[*] Starting File Integrity Tracking on: {path_to_watch}")
    event_handler = SensitiveDirectoryHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()


# =====================================================================
# 4. MAIN ORCHESTRATOR (Execution starts here)
# =====================================================================
if __name__ == "__main__":
    print("=== Launching Cyber Threat Detection Agent (Module 1) ===")
    
    # 1. Start Network Sniffer
    start_network_sniffing(interface=None) 
    
    # 2. Start File System Watcher (Watching the current project folder for testing)
    start_file_monitoring(path_to_watch="./") 
    
    # 3. Start Process Monitor in a separate background thread
    process_thread = threading.Thread(target=monitor_new_processes, daemon=True)
    process_thread.start()
    
    # Keep the main service alive so threads can keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopping Monitoring Service...")