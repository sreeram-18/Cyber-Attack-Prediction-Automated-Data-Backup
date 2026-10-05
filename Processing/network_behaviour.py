"""
network_behaviour.py

Reads completed network flows from:
    Collectors/network_flows.jsonl

Creates time-windowed network behaviour records in:
    Processing/network_windows.jsonl

Designed to work with the current network_collector.py schema.
"""

import json
import os
import time
from datetime import datetime
from collections import Counter, defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLOW_FILE = os.path.join(
    BASE_DIR,
    "Collectors",
    "network_flows.jsonl"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "Processing",
    "network_windows.jsonl"
)

WINDOW_SIZE = 10          # seconds
POLL_INTERVAL = 2         # seconds


# ============================================================
# SAFE HELPERS
# ============================================================

def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_bool(value):
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")

    return bool(value)


def safe_rate(numerator, denominator):
    if denominator <= 0:
        return 0.0

    return numerator / denominator


def parse_timestamp(value):
    """
    Converts ISO timestamp to datetime.
    Supports timestamps ending in Z.
    """

    if not value:
        return None

    try:
        value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


# ============================================================
# FILE READING
# ============================================================

def read_new_flows(file_position):
    """
    Read only flows added since the previous read.

    Returns:
        flows
        new_file_position
    """

    flows = []

    if not os.path.exists(FLOW_FILE):
        return flows, file_position

    try:
        with open(FLOW_FILE, "r", encoding="utf-8") as f:

            f.seek(file_position)

            while True:

                line = f.readline()

                if not line:
                    break

                line = line.strip()

                if not line:
                    continue

                try:
                    flow = json.loads(line)

                    if not isinstance(flow, dict):
                        continue

                    # The collector always provides flow_id.
                    if not flow.get("flow_id"):
                        print("[WARNING] Flow without flow_id skipped.")
                        continue

                    flows.append(flow)

                except json.JSONDecodeError:
                    print("[WARNING] Invalid JSON flow skipped.")

            new_position = f.tell()

        return flows, new_position

    except PermissionError:
        print("[ERROR] Permission denied while reading network flow file.")
        return [], file_position

    except Exception as e:
        print(f"[ERROR] Could not read flow file: {e}")
        return [], file_position


# ============================================================
# FLOW NORMALIZATION
# ============================================================

def normalize_flow(flow):
    """
    Normalize the collector's flow structure.

    IMPORTANT:
    Your collector uses packet_count, not packets.
    """

    start_time = parse_timestamp(flow.get("start_time"))
    end_time = parse_timestamp(flow.get("end_time"))

    if start_time is None:
        return None

    packet_count = safe_int(flow.get("packet_count"))
    total_bytes = safe_int(flow.get("total_bytes"))

    forward_packets = safe_int(flow.get("forward_packets"))
    backward_packets = safe_int(flow.get("backward_packets"))

    forward_bytes = safe_int(flow.get("forward_bytes"))
    backward_bytes = safe_int(flow.get("backward_bytes"))

    duration = safe_float(flow.get("duration"))

    # If duration wasn't supplied correctly, calculate it.
    if duration <= 0 and end_time is not None:
        duration = max(
            0.0,
            (end_time - start_time).total_seconds()
        )

    return {
        "flow_id": flow.get("flow_id"),

        "start_time": start_time,
        "end_time": end_time,

        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),

        "src_port": safe_int(flow.get("src_port")),
        "dst_port": safe_int(flow.get("dst_port")),

        "protocol": str(flow.get("protocol", "UNKNOWN")),
        "service": str(flow.get("service", "UNKNOWN")),

        # ------------------------------
        # Packet / byte statistics
        # ------------------------------

        "packet_count": packet_count,

        "forward_packets": forward_packets,
        "backward_packets": backward_packets,

        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,

        "total_bytes": total_bytes,

        "min_packet_size": safe_int(
            flow.get("min_packet_size")
        ),

        "max_packet_size": safe_int(
            flow.get("max_packet_size")
        ),

        "average_packet_size": safe_float(
            flow.get("average_packet_size")
        ),

        # ------------------------------
        # TCP flags
        # ------------------------------

        "syn_count": safe_int(flow.get("syn_count")),
        "ack_count": safe_int(flow.get("ack_count")),
        "fin_count": safe_int(flow.get("fin_count")),
        "rst_count": safe_int(flow.get("rst_count")),
        "psh_count": safe_int(flow.get("psh_count")),
        "urg_count": safe_int(flow.get("urg_count")),

        # ------------------------------
        # Protocol
        # ------------------------------

        "is_tcp": safe_bool(flow.get("is_tcp")),
        "is_udp": safe_bool(flow.get("is_udp")),
        "is_icmp": safe_bool(flow.get("is_icmp")),

        # ------------------------------
        # Rates
        # ------------------------------

        "packets_per_second": safe_float(
            flow.get("packets_per_second")
        ),

        "bytes_per_second": safe_float(
            flow.get("bytes_per_second")
        ),

        "forward_bytes_per_second": safe_float(
            flow.get("forward_bytes_per_second")
        ),

        "backward_bytes_per_second": safe_float(
            flow.get("backward_bytes_per_second")
        ),

        # ------------------------------
        # Flags
        # ------------------------------

        "is_single_packet": safe_bool(
            flow.get("is_single_packet")
        ),

        "has_syn": safe_bool(
            flow.get("has_syn")
        ),

        "has_rst": safe_bool(
            flow.get("has_rst")
        ),

        "has_fin": safe_bool(
            flow.get("has_fin")
        ),

        "duration": duration,
    }


# ============================================================
# WINDOW FEATURE CALCULATION
# ============================================================

def create_window(flows, window_start, window_end):
    """
    Create one aggregated network behaviour window.
    """

    if not flows:
        return None

    # ========================================================
    # BASIC COUNTS
    # ========================================================

    total_flows = len(flows)

    tcp_flows = sum(
        1 for f in flows if f["is_tcp"]
    )

    udp_flows = sum(
        1 for f in flows if f["is_udp"]
    )

    icmp_flows = sum(
        1 for f in flows if f["is_icmp"]
    )

    # ========================================================
    # UNIQUE NETWORK ENTITIES
    # ========================================================

    destination_ips = set()
    source_ips = set()

    destination_ports = set()
    source_ports = set()

    services = Counter()

    for f in flows:

        if f["src_ip"]:
            source_ips.add(f["src_ip"])

        if f["dst_ip"]:
            destination_ips.add(f["dst_ip"])

        if f["src_port"] > 0:
            source_ports.add(f["src_port"])

        if f["dst_port"] > 0:
            destination_ports.add(f["dst_port"])

        services[f["service"]] += 1

    # ========================================================
    # PACKETS
    # ========================================================

    total_packets = sum(
        f["packet_count"] for f in flows
    )

    forward_packets = sum(
        f["forward_packets"] for f in flows
    )

    backward_packets = sum(
        f["backward_packets"] for f in flows
    )

    # ========================================================
    # BYTES
    # ========================================================

    total_bytes = sum(
        f["total_bytes"] for f in flows
    )

    forward_bytes = sum(
        f["forward_bytes"] for f in flows
    )

    backward_bytes = sum(
        f["backward_bytes"] for f in flows
    )

    # ========================================================
    # DURATIONS
    # ========================================================

    durations = [
        f["duration"]
        for f in flows
    ]

    average_duration = safe_rate(
        sum(durations),
        len(durations)
    )

    max_duration = max(
        durations,
        default=0.0
    )

    min_duration = min(
        durations,
        default=0.0
    )

    # ========================================================
    # PACKET SIZE
    # ========================================================

    packet_sizes = [
        f["average_packet_size"]
        for f in flows
        if f["average_packet_size"] > 0
    ]

    average_packet_size = safe_rate(
        sum(packet_sizes),
        len(packet_sizes)
    )

    min_packet_size = min(
        (
            f["min_packet_size"]
            for f in flows
            if f["min_packet_size"] > 0
        ),
        default=0
    )

    max_packet_size = max(
        (
            f["max_packet_size"]
            for f in flows
            if f["max_packet_size"] > 0
        ),
        default=0
    )

    # ========================================================
    # TCP FLAGS
    # ========================================================

    syn_count = sum(
        f["syn_count"] for f in flows
    )

    ack_count = sum(
        f["ack_count"] for f in flows
    )

    fin_count = sum(
        f["fin_count"] for f in flows
    )

    rst_count = sum(
        f["rst_count"] for f in flows
    )

    psh_count = sum(
        f["psh_count"] for f in flows
    )

    urg_count = sum(
        f["urg_count"] for f in flows
    )

    # ========================================================
    # FLOW FLAGS
    # ========================================================

    single_packet_flows = sum(
        1 for f in flows
        if f["is_single_packet"]
    )

    flows_with_syn = sum(
        1 for f in flows
        if f["has_syn"]
    )

    flows_with_rst = sum(
        1 for f in flows
        if f["has_rst"]
    )

    flows_with_fin = sum(
        1 for f in flows
        if f["has_fin"]
    )

    # ========================================================
    # RATES
    # ========================================================

    actual_window_seconds = max(
        0.001,
        (window_end - window_start).total_seconds()
    )

    flows_per_second = safe_rate(
        total_flows,
        actual_window_seconds
    )

    packets_per_second = safe_rate(
        total_packets,
        actual_window_seconds
    )

    bytes_per_second = safe_rate(
        total_bytes,
        actual_window_seconds
    )

    # ========================================================
    # PACKET DIRECTION RATIOS
    # ========================================================

    forward_packet_ratio = safe_rate(
        forward_packets,
        total_packets
    )

    backward_packet_ratio = safe_rate(
        backward_packets,
        total_packets
    )

    forward_byte_ratio = safe_rate(
        forward_bytes,
        total_bytes
    )

    backward_byte_ratio = safe_rate(
        backward_bytes,
        total_bytes
    )

    # ========================================================
    # TCP ERROR / FLAG RATES
    # ========================================================

    syn_rate = safe_rate(
        syn_count,
        total_flows
    )

    rst_rate = safe_rate(
        rst_count,
        total_flows
    )

    fin_rate = safe_rate(
        fin_count,
        total_flows
    )

    psh_rate = safe_rate(
        psh_count,
        total_packets
    )

    # ========================================================
    # SERVICE FEATURES
    # ========================================================

    https_flows = sum(
        1 for f in flows
        if f["service"].upper() == "HTTPS"
    )

    http_flows = sum(
        1 for f in flows
        if f["service"].upper() == "HTTP"
    )

    dns_flows = sum(
        1 for f in flows
        if f["service"].upper() == "DNS"
    )

    ssh_flows = sum(
        1 for f in flows
        if f["service"].upper() == "SSH"
    )

    # ========================================================
    # SOURCE / DESTINATION BEHAVIOUR
    # ========================================================

    src_flow_counts = Counter(
        f["src_ip"]
        for f in flows
        if f["src_ip"]
    )

    dst_flow_counts = Counter(
        f["dst_ip"]
        for f in flows
        if f["dst_ip"]
    )

    max_flows_per_source = max(
        src_flow_counts.values(),
        default=0
    )

    max_flows_per_destination = max(
        dst_flow_counts.values(),
        default=0
    )

    # ========================================================
    # NSL-KDD RELATED SERVICE STATISTICS
    # ========================================================

    service_counts = Counter(
        f["service"]
        for f in flows
    )

    same_service_flows = sum(
        count * count
        for count in service_counts.values()
    )

    same_service_rate = safe_rate(
        same_service_flows,
        total_flows * total_flows
    )

    # ========================================================
    # SERIALIZABLE RESULT
    # ========================================================

    result = {

        # ----------------------------------------------------
        # Window information
        # ----------------------------------------------------

        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "window_duration": actual_window_seconds,

        # ----------------------------------------------------
        # Flow statistics
        # ----------------------------------------------------

        "flow_count": total_flows,

        "tcp_flows": tcp_flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,

        "flows_per_second": flows_per_second,

        # ----------------------------------------------------
        # Network entities
        # ----------------------------------------------------

        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),

        "unique_source_ports": len(source_ports),
        "unique_destination_ports": len(destination_ports),

        "max_flows_per_source": max_flows_per_source,
        "max_flows_per_destination": max_flows_per_destination,

        # ----------------------------------------------------
        # Packet statistics
        # ----------------------------------------------------

        "total_packets": total_packets,
        "forward_packets": forward_packets,
        "backward_packets": backward_packets,

        "packets_per_second": packets_per_second,

        "forward_packet_ratio": forward_packet_ratio,
        "backward_packet_ratio": backward_packet_ratio,

        # ----------------------------------------------------
        # Byte statistics
        # ----------------------------------------------------

        "total_bytes": total_bytes,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,

        "bytes_per_second": bytes_per_second,

        "forward_byte_ratio": forward_byte_ratio,
        "backward_byte_ratio": backward_byte_ratio,

        # ----------------------------------------------------
        # Duration
        # ----------------------------------------------------

        "average_flow_duration": average_duration,
        "minimum_flow_duration": min_duration,
        "maximum_flow_duration": max_duration,

        # ----------------------------------------------------
        # Packet size
        # ----------------------------------------------------

        "average_packet_size": average_packet_size,
        "minimum_packet_size": min_packet_size,
        "maximum_packet_size": max_packet_size,

        # ----------------------------------------------------
        # TCP flags
        # ----------------------------------------------------

        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,

        # ----------------------------------------------------
        # Flag rates
        # ----------------------------------------------------

        "syn_rate": syn_rate,
        "rst_rate": rst_rate,
        "fin_rate": fin_rate,
        "psh_rate": psh_rate,

        # ----------------------------------------------------
        # Flow flag counts
        # ----------------------------------------------------

        "single_packet_flows": single_packet_flows,
        "flows_with_syn": flows_with_syn,
        "flows_with_rst": flows_with_rst,
        "flows_with_fin": flows_with_fin,

        # ----------------------------------------------------
        # Services
        # ----------------------------------------------------

        "service_count": len(services),

        "https_flows": https_flows,
        "http_flows": http_flows,
        "dns_flows": dns_flows,
        "ssh_flows": ssh_flows,

        "same_service_rate": same_service_rate,

        # ----------------------------------------------------
        # Service distribution
        # ----------------------------------------------------

        "services": dict(services),
    }

    return result


# ============================================================
# PRINT WINDOW
# ============================================================

def print_window(window):
    print()
    print("==========================================")
    print("       NETWORK BEHAVIOUR WINDOW")
    print("==========================================")

    print(f"Flows                 : {window['flow_count']}")
    print(f"TCP flows             : {window['tcp_flows']}")
    print(f"UDP flows             : {window['udp_flows']}")
    print(f"ICMP flows            : {window['icmp_flows']}")

    print(
        f"Unique source IPs     : "
        f"{window['unique_source_ips']}"
    )

    print(
        f"Unique destination IPs: "
        f"{window['unique_destination_ips']}"
    )

    print(
        f"Unique source ports   : "
        f"{window['unique_source_ports']}"
    )

    print(
        f"Unique destination ports: "
        f"{window['unique_destination_ports']}"
    )

    print(
        f"Total packets         : "
        f"{window['total_packets']}"
    )

    print(
        f"Forward packets       : "
        f"{window['forward_packets']}"
    )

    print(
        f"Backward packets      : "
        f"{window['backward_packets']}"
    )

    print(
        f"Total bytes           : "
        f"{window['total_bytes']}"
    )

    print(
        f"Forward bytes         : "
        f"{window['forward_bytes']}"
    )

    print(
        f"Backward bytes        : "
        f"{window['backward_bytes']}"
    )

    print(
        f"Average flow duration : "
        f"{window['average_flow_duration']:.3f}s"
    )

    print(
        f"Average packet size   : "
        f"{window['average_packet_size']:.2f}"
    )

    print(
        f"Packets/sec           : "
        f"{window['packets_per_second']:.2f}"
    )

    print(
        f"Bytes/sec             : "
        f"{window['bytes_per_second']:.2f}"
    )

    print(
        f"SYN count             : "
        f"{window['syn_count']}"
    )

    print(
        f"ACK count             : "
        f"{window['ack_count']}"
    )

    print(
        f"FIN count             : "
        f"{window['fin_count']}"
    )

    print(
        f"RST count             : "
        f"{window['rst_count']}"
    )

    print(
        f"PSH count             : "
        f"{window['psh_count']}"
    )

    print(
        f"URG count             : "
        f"{window['urg_count']}"
    )

    print(
        f"SYN rate              : "
        f"{window['syn_rate']:.2f}"
    )

    print(
        f"RST rate              : "
        f"{window['rst_rate']:.2f}"
    )

    print(
        f"Flows/sec             : "
        f"{window['flows_per_second']:.2f}"
    )

    print(
        f"Services              : "
        f"{window['service_count']}"
    )

    print(
        f"HTTPS flows           : "
        f"{window['https_flows']}"
    )

    print("------------------------------------------")
    print(f"Output: {OUTPUT_FILE}")
    print("==========================================")
    print()


# ============================================================
# OUTPUT
# ============================================================

def save_window(window):
    try:

        os.makedirs(
            os.path.dirname(OUTPUT_FILE),
            exist_ok=True
        )

        with open(
            OUTPUT_FILE,
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                json.dumps(
                    window,
                    separators=(",", ":")
                )
                + "\n"
            )

    except Exception as e:
        print(
            f"[ERROR] Could not write network window: {e}"
        )


# ============================================================
# MAIN
# ============================================================

def run():

    print("==========================================")
    print("   NETWORK BEHAVIOUR MONITOR STARTED")
    print("==========================================")
    print(f"Flow file    : {FLOW_FILE}")
    print(f"Output file  : {OUTPUT_FILE}")
    print(f"Window size  : {WINDOW_SIZE} seconds")
    print("------------------------------------------")

    file_position = 0

    current_flows = []

    window_start = datetime.now()

    # --------------------------------------------------------
    # Initial read
    # --------------------------------------------------------

    flows, file_position = read_new_flows(file_position)

    if flows:

        normalized = []

        for flow in flows:

            f = normalize_flow(flow)

            if f is not None:
                normalized.append(f)

        current_flows.extend(normalized)

        print(
            f"[INFO] Added {len(normalized)} new flows."
        )

    else:

        print(
            "[INFO] No new completed flows found."
        )

    # --------------------------------------------------------
    # Monitoring loop
    # --------------------------------------------------------

    try:

        while True:

            time.sleep(POLL_INTERVAL)

            # ----------------------------------------------
            # Read newly completed flows
            # ----------------------------------------------

            flows, new_position = read_new_flows(
                file_position
            )

            if flows:

                normalized = []

                for flow in flows:

                    f = normalize_flow(flow)

                    if f is not None:
                        normalized.append(f)

                current_flows.extend(normalized)

                file_position = new_position

                print(
                    f"[INFO] Added "
                    f"{len(normalized)} new flows."
                )

            else:

                print(
                    "[INFO] No new completed flows found."
                )

            # ----------------------------------------------
            # Check window
            # ----------------------------------------------

            now = datetime.now()

            elapsed = (
                now - window_start
            ).total_seconds()

            if elapsed >= WINDOW_SIZE:

                if current_flows:

                    window = create_window(
                        current_flows,
                        window_start,
                        now
                    )

                    if window:

                        print_window(window)
                        save_window(window)

                    current_flows = []

                else:

                    print(
                        "[INFO] Window completed "
                        "but contained no flows."
                    )

                window_start = now

    except KeyboardInterrupt:

        print()
        print(
            "Stopping network behaviour monitor..."
        )

        # ----------------------------------------------------
        # Save remaining flows
        # ----------------------------------------------------

        if current_flows:

            now = datetime.now()

            window = create_window(
                current_flows,
                window_start,
                now
            )

            if window:

                print_window(window)
                save_window(window)

        print(
            "Network behaviour monitor stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    run()