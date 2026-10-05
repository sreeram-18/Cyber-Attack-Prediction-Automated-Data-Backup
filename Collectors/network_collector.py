from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import threading
import time
import json
import hashlib


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = None

# A flow is finalized after this many seconds without new packets
FLOW_TIMEOUT = 10

OUTPUT_FILE = "network_flows.jsonl"


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# PROTOCOL MAPPING
# ============================================================

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP"
}


def get_protocol_name(packet):
    """
    Return a readable protocol name.
    """

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    if ICMP in packet:
        return "ICMP"

    if IP in packet:
        return PROTOCOL_NAMES.get(
            packet[IP].proto,
            f"OTHER-{packet[IP].proto}"
        )

    return "UNKNOWN"


# ============================================================
# SERVICE MAPPING
# ============================================================

COMMON_SERVICES = {

    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC"
}


def get_service(src_port, dst_port):

    if dst_port in COMMON_SERVICES:
        return COMMON_SERVICES[dst_port]

    if src_port in COMMON_SERVICES:
        return COMMON_SERVICES[src_port]

    return "UNKNOWN"


# ============================================================
# FLOW ID
# ============================================================

def generate_flow_id(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    timestamp
):

    value = (
        f"{src_ip}-"
        f"{dst_ip}-"
        f"{src_port}-"
        f"{dst_port}-"
        f"{protocol}-"
        f"{timestamp.timestamp()}"
    )

    return hashlib.sha256(
        value.encode()
    ).hexdigest()[:16]


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):

    if IP not in packet:
        return None

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst

    src_port = 0
    dst_port = 0

    protocol = get_protocol_name(packet)

    if TCP in packet:

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    endpoint_a = (
        src_ip,
        src_port
    )

    endpoint_b = (
        dst_ip,
        dst_port
    )

    # Make the flow bidirectional
    # so A -> B and B -> A belong
    # to the same flow.

    if endpoint_a <= endpoint_b:

        return (
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol
        )

    return (
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol
    )


# ============================================================
# CREATE FLOW
# ============================================================

def create_flow(packet, timestamp):

    ip = packet[IP]

    src_ip = ip.src
    dst_ip = ip.dst

    src_port = 0
    dst_port = 0

    protocol = get_protocol_name(packet)

    if TCP in packet:

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport


    flow_id = generate_flow_id(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        timestamp
    )


    return {

        # ----------------------------------------------------
        # Identification
        # ----------------------------------------------------

        "flow_id": flow_id,

        "start_time": timestamp.isoformat(),

        "end_time": timestamp.isoformat(),

        "last_seen": timestamp.isoformat(),


        # ----------------------------------------------------
        # Connection information
        # ----------------------------------------------------

        "src_ip": src_ip,

        "dst_ip": dst_ip,

        "src_port": src_port,

        "dst_port": dst_port,

        "protocol": protocol,

        "service": get_service(
            src_port,
            dst_port
        ),


        # ----------------------------------------------------
        # Traffic statistics
        # ----------------------------------------------------

        "packet_count": 0,

        "forward_packets": 0,

        "backward_packets": 0,

        "forward_bytes": 0,

        "backward_bytes": 0,

        "total_bytes": 0,


        # ----------------------------------------------------
        # Packet-size statistics
        # ----------------------------------------------------

        "min_packet_size": None,

        "max_packet_size": None,

        "packet_sizes": [],


        # ----------------------------------------------------
        # TCP flags
        # ----------------------------------------------------

        "syn_count": 0,

        "ack_count": 0,

        "fin_count": 0,

        "rst_count": 0,

        "psh_count": 0,

        "urg_count": 0,


        # ----------------------------------------------------
        # Flow status
        # ----------------------------------------------------

        "is_tcp": protocol == "TCP",

        "is_udp": protocol == "UDP",

        "is_icmp": protocol == "ICMP"

    }


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow, packet, timestamp):

    ip = packet[IP]

    packet_size = len(packet)

    flow["packet_count"] += 1

    flow["end_time"] = timestamp.isoformat()

    flow["last_seen"] = timestamp.isoformat()


    # ========================================================
    # Direction
    # ========================================================

    if (

        ip.src == flow["src_ip"]

        and

        ip.dst == flow["dst_ip"]

    ):

        flow["forward_packets"] += 1

        flow["forward_bytes"] += packet_size

    else:

        flow["backward_packets"] += 1

        flow["backward_bytes"] += packet_size


    # ========================================================
    # Packet size
    # ========================================================

    flow["packet_sizes"].append(
        packet_size
    )


    if (

        flow["min_packet_size"] is None

        or

        packet_size < flow["min_packet_size"]

    ):

        flow["min_packet_size"] = packet_size


    if (

        flow["max_packet_size"] is None

        or

        packet_size > flow["max_packet_size"]

    ):

        flow["max_packet_size"] = packet_size


    # ========================================================
    # TCP flags
    # ========================================================

    if TCP in packet:

        flags = packet[TCP].flags


        # SYN
        if flags & 0x02:
            flow["syn_count"] += 1


        # ACK
        if flags & 0x10:
            flow["ack_count"] += 1


        # FIN
        if flags & 0x01:
            flow["fin_count"] += 1


        # RST
        if flags & 0x04:
            flow["rst_count"] += 1


        # PSH
        if flags & 0x08:
            flow["psh_count"] += 1


        # URG
        if flags & 0x20:
            flow["urg_count"] += 1


# ============================================================
# FINALIZE FLOW
# ============================================================

def finalize_flow(flow):

    start = datetime.fromisoformat(
        flow["start_time"]
    )

    end = datetime.fromisoformat(
        flow["end_time"]
    )


    # ========================================================
    # Duration
    # ========================================================

    duration = (
        end - start
    ).total_seconds()


    flow["duration"] = duration


    # ========================================================
    # Total bytes
    # ========================================================

    flow["total_bytes"] = (

        flow["forward_bytes"]

        +

        flow["backward_bytes"]

    )


    # ========================================================
    # Average packet size
    # ========================================================

    if flow["packet_count"] > 0:

        flow["average_packet_size"] = (

            flow["total_bytes"]

            /

            flow["packet_count"]

        )

    else:

        flow["average_packet_size"] = 0


    # ========================================================
    # Traffic rates
    # ========================================================

    if duration > 0:

        flow["packets_per_second"] = (

            flow["packet_count"]

            /

            duration

        )

        flow["bytes_per_second"] = (

            flow["total_bytes"]

            /

            duration

        )

        flow["forward_bytes_per_second"] = (

            flow["forward_bytes"]

            /

            duration

        )

        flow["backward_bytes_per_second"] = (

            flow["backward_bytes"]

            /

            duration

        )

    else:

        flow["packets_per_second"] = 0

        flow["bytes_per_second"] = 0

        flow["forward_bytes_per_second"] = 0

        flow["backward_bytes_per_second"] = 0


    # ========================================================
    # Flow status
    # ========================================================

    flow["is_single_packet"] = (
        flow["packet_count"] == 1
    )


    flow["has_syn"] = (
        flow["syn_count"] > 0
    )


    flow["has_rst"] = (
        flow["rst_count"] > 0
    )


    flow["has_fin"] = (
        flow["fin_count"] > 0
    )


    # ========================================================
    # Remove raw packet-size list
    # ========================================================

    # We don't need to store every packet size
    # in the final flow record.

    flow.pop(
        "packet_sizes",
        None
    )


    return flow


# ============================================================
# SAVE FLOW
# ============================================================

def save_flow(flow):

    finalized = finalize_flow(
        flow
    )


    with open(
        OUTPUT_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                finalized
            )

            +

            "\n"
        )


    # ========================================================
    # Console output
    # ========================================================

    print("\n==========================================")

    print("[FLOW COMPLETED]")

    print("==========================================")


    print(
        f"Flow ID      : "
        f"{finalized['flow_id']}"
    )


    print(
        f"Connection   : "
        f"{finalized['src_ip']}:"
        f"{finalized['src_port']}"
        f" -> "
        f"{finalized['dst_ip']}:"
        f"{finalized['dst_port']}"
    )


    print(
        f"Protocol     : "
        f"{finalized['protocol']}"
    )


    print(
        f"Service      : "
        f"{finalized['service']}"
    )


    print(
        f"Duration     : "
        f"{finalized['duration']:.3f}s"
    )


    print(
        f"Packets      : "
        f"{finalized['packet_count']}"
    )


    print(
        f"Forward      : "
        f"{finalized['forward_packets']}"
    )


    print(
        f"Backward     : "
        f"{finalized['backward_packets']}"
    )


    print(
        f"Total bytes  : "
        f"{finalized['total_bytes']}"
    )


    print(
        f"Avg packet   : "
        f"{finalized['average_packet_size']:.2f}"
    )


    print(
        f"SYN/ACK/FIN/RST : "
        f"{finalized['syn_count']}/"
        f"{finalized['ack_count']}/"
        f"{finalized['fin_count']}/"
        f"{finalized['rst_count']}"
    )


    print(
        f"Packets/sec  : "
        f"{finalized['packets_per_second']:.2f}"
    )


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):

    if IP not in packet:

        return


    timestamp = datetime.now()


    key = get_flow_key(
        packet
    )


    if key is None:

        return


    # ========================================================
    # Create new flow
    # ========================================================

    if key not in flows:

        flows[key] = create_flow(
            packet,
            timestamp
        )


    # ========================================================
    # Update existing flow
    # ========================================================

    update_flow(
        flows[key],
        packet,
        timestamp
    )


# ============================================================
# CLEANUP THREAD
# ============================================================

def cleanup_flows():

    while True:

        current_time = datetime.now()


        expired = []


        for key, flow in list(
            flows.items()
        ):

            last_seen = datetime.fromisoformat(
                flow["last_seen"]
            )


            inactive_time = (

                current_time

                -

                last_seen

            ).total_seconds()


            if inactive_time >= FLOW_TIMEOUT:

                expired.append(
                    key
                )


        # ====================================================
        # Finalize expired flows
        # ====================================================

        for key in expired:

            flow = flows.pop(
                key,
                None
            )


            if flow:

                save_flow(
                    flow
                )


        time.sleep(1)


# ============================================================
# START NETWORK MONITOR
# ============================================================

def start_network_monitor():

    print("==========================================")

    print("     NETWORK MONITORING STARTED")

    print("==========================================")


    print(
        f"Interface      : {INTERFACE}"
    )


    print(
        f"Flow timeout   : "
        f"{FLOW_TIMEOUT} seconds"
    )


    print(
        f"Output file    : "
        f"{OUTPUT_FILE}"
    )


    print("------------------------------------------")


    # ========================================================
    # Start cleanup thread
    # ========================================================

    cleanup_thread = threading.Thread(

        target=cleanup_flows,

        daemon=True

    )


    cleanup_thread.start()


    # ========================================================
    # Start packet capture
    # ========================================================

    sniff(

        iface=INTERFACE,

        prn=process_packet,

        store=False

    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        start_network_monitor()

    except KeyboardInterrupt:

        print("\n")

        print(
            "Stopping network monitor..."
        )


        # ====================================================
        # Save remaining active flows
        # ====================================================

        for key in list(
            flows.keys()
        ):

            flow = flows.pop(
                key
            )


            save_flow(
                flow
            )


        print(
            "Network monitor stopped."
        )