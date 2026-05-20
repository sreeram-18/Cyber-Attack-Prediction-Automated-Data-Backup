from scapy.all import sniff, IP, TCP, UDP
import threading

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
            
        # This dictionary is what your ML Feature Extraction module will consume
        packet_metadata = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": len(packet)
        }
        
        # TODO: Pass packet_metadata to your ML pre-processor queue here
        # print(packet_metadata) # Uncomment for debugging, but disable in production to save CPU

def start_network_sniffing(interface=None):
    """Starts packet sniffing in a non-blocking background thread."""
    print("[*] Starting Real-Time Packet Sniffing...")
    # store=0 ensures packets are dropped from RAM immediately after the callback executes
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={"iface": interface, "prn": process_packet, "store": 0}, 
        daemon=True
    )
    sniff_thread.start()