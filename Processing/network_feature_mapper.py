"""
network_feature_mapper.py

Converts network behaviour windows into:
1. NSL-KDD-compatible / NSL-KDD-inspired network features
2. Additional real-time network telemetry

IMPORTANT:
The collector's current network_windows.jsonl schema uses names such as
tcp_flow_count, avg_flow_duration, https_flow_count, etc. This mapper
reads those names directly and also supports the older mapper schema.
"""

import json
import os
from collections import Counter


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(BASE_DIR, "Processing", "network_windows.jsonl")
OUTPUT_FILE = os.path.join(BASE_DIR, "Processing", "ml_network_features.jsonl")


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


def safe_rate(numerator, denominator):
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def clamp(value, minimum=0.0, maximum=1.0):
    return max(minimum, min(maximum, value))


def first_value(data, *names, default=None):
    """Return the first usable value from the supplied field names."""
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return default


# ------------------------------------------------------------------
# SERVICE MAPPING
# ------------------------------------------------------------------

SERVICE_FIELDS = {
    "https": ("https_flow_count", "https_flows"),
    "http": ("http_flow_count", "http_flows"),
    "dns": ("dns_flow_count", "dns_flows"),
    "ssh": ("ssh_flow_count", "ssh_flows"),
    "rdp": ("rdp_flow_count", "rdp_flows"),
    "smb": ("smb_flow_count", "smb_flows"),
}


def get_service_counts(window):
    counts = {}

    # Current collector schema
    for service, fields in SERVICE_FIELDS.items():
        count = safe_int(first_value(window, *fields, default=0))
        if count > 0:
            counts[service] = count

    # Older schema support
    services = window.get("services")
    if isinstance(services, dict):
        for service, count in services.items():
            service = str(service).strip().lower()
            count = safe_int(count)
            if count > 0:
                counts[service] = max(counts.get(service, 0), count)

    return counts


def determine_service(window):
    counts = get_service_counts(window)

    if not counts:
        return "unknown"

    return max(counts, key=counts.get)


# ------------------------------------------------------------------
# PROTOCOL MAPPING
# ------------------------------------------------------------------

def determine_protocol(window):
    tcp = safe_int(first_value(
        window, "tcp_flow_count", "tcp_flows", default=0
    ))
    udp = safe_int(first_value(
        window, "udp_flow_count", "udp_flows", default=0
    ))
    icmp = safe_int(first_value(
        window, "icmp_flow_count", "icmp_flows", default=0
    ))

    counts = {
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
    }

    if sum(counts.values()) <= 0:
        return "unknown"

    return max(counts, key=counts.get)


# ------------------------------------------------------------------
# FLAG MAPPING
# ------------------------------------------------------------------

def determine_flag(window):
    flow_count = safe_int(window.get("flow_count", 0))

    if flow_count <= 0:
        return "OTH"

    tcp_flows = safe_int(first_value(
        window, "tcp_flow_count", "tcp_flows", default=0
    ))

    if tcp_flows <= 0:
        return "OTH"

    syn_flows = safe_int(first_value(
        window, "syn_flow_count", "flows_with_syn", default=0
    ))
    rst_flows = safe_int(first_value(
        window, "rst_flow_count", "flows_with_rst", default=0
    ))
    fin_flows = safe_int(first_value(
        window, "fin_flow_count", "flows_with_fin", default=0
    ))

    syn_count = safe_int(window.get("syn_count", 0))
    ack_count = safe_int(window.get("ack_count", 0))
    rst_count = safe_int(window.get("rst_count", 0))

    # A flow that contains SYN + RST is most consistent with rejection.
    if rst_flows > 0 and syn_flows > 0:
        return "REJ"

    # SYN traffic with ACK activity indicates established/finished TCP
    # traffic rather than a pure half-open attempt.
    if syn_flows > 0:
        if ack_count > 0:
            return "SF"
        return "S0"

    if fin_flows > 0:
        return "SF"

    # ACK/RST-only traffic does not give enough information for a
    # more specific NSL-KDD flag.
    if rst_count > 0:
        return "RSTO"

    if ack_count > 0:
        return "SF"

    return "OTH"


# ------------------------------------------------------------------
# MAIN MAPPING
# ------------------------------------------------------------------

def map_window(window):
    flow_count = safe_int(window.get("flow_count", 0))

    total_packets = safe_int(window.get("total_packets", 0))
    total_bytes = safe_int(window.get("total_bytes", 0))

    forward_packets = safe_int(window.get("forward_packets", 0))
    backward_packets = safe_int(window.get("backward_packets", 0))

    forward_bytes = safe_int(window.get("forward_bytes", 0))
    backward_bytes = safe_int(window.get("backward_bytes", 0))

    tcp_flows = safe_int(first_value(
        window, "tcp_flow_count", "tcp_flows", default=0
    ))
    udp_flows = safe_int(first_value(
        window, "udp_flow_count", "udp_flows", default=0
    ))
    icmp_flows = safe_int(first_value(
        window, "icmp_flow_count", "icmp_flows", default=0
    ))

    avg_duration = safe_float(first_value(
        window, "avg_flow_duration", "average_flow_duration", default=0.0
    ))

    protocol_type = determine_protocol(window)
    service_counts = get_service_counts(window)
    service = determine_service(window)

    srv_count = service_counts.get(service, 0)

    # If the service is unknown, there is no valid service denominator.
    if service == "unknown":
        srv_count = 0

    flag = determine_flag(window)

    syn_flow_count = safe_int(first_value(
        window, "syn_flow_count", "flows_with_syn", default=0
    ))
    rst_flow_count = safe_int(first_value(
        window, "rst_flow_count", "flows_with_rst", default=0
    ))

    fin_flow_count = safe_int(first_value(
        window, "fin_flow_count", "flows_with_fin", default=0
    ))

    urgent = safe_int(window.get("urg_count", 0))

    # NSL-KDD-style basic fields
    duration = avg_duration
    src_bytes = forward_bytes
    dst_bytes = backward_bytes
    count = flow_count

    # These cannot be reconstructed accurately from the current
    # behaviour window schema.
    land = None
    wrong_fragment = None

    serror_rate = clamp(safe_rate(syn_flow_count, flow_count))
    rerror_rate = clamp(safe_rate(rst_flow_count, flow_count))

    same_srv_rate = clamp(safe_rate(srv_count, flow_count))
    diff_srv_rate = clamp(1.0 - same_srv_rate) if flow_count > 0 else 0.0

    # The current collector does not retain enough per-service/per-host
    # history to calculate these NSL-KDD features without fabrication.
    srv_serror_rate = None
    srv_rerror_rate = None
    srv_diff_host_rate = None
    dst_host_srv_count = None
    dst_host_same_srv_rate = None
    dst_host_diff_srv_rate = None
    dst_host_same_src_port_rate = None
    dst_host_srv_diff_host_rate = None
    dst_host_serror_rate = None
    dst_host_srv_serror_rate = None
    dst_host_rerror_rate = None
    dst_host_srv_rerror_rate = None

    dst_host_count = safe_int(window.get("unique_destination_ips", 0))

    # ------------------------------------------------------------------
    # Additional telemetry
    # ------------------------------------------------------------------

    additional_features = {
        "flow_count": flow_count,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "forward_packets": forward_packets,
        "backward_packets": backward_packets,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,

        "window_duration": safe_float(
            window.get("window_duration", 0.0)
        ),
        "avg_flow_duration": avg_duration,
        "avg_packets_per_flow": safe_float(
            window.get("avg_packets_per_flow", 0.0)
        ),
        "avg_bytes_per_flow": safe_float(
            window.get("avg_bytes_per_flow", 0.0)
        ),
        "avg_packet_size": safe_float(
            window.get("avg_packet_size", 0.0)
        ),

        "minimum_packet_size": safe_int(
            first_value(
                window,
                "minimum_packet_size",
                "min_packet_size",
                default=0
            )
        ),
        "maximum_packet_size": safe_int(
            first_value(
                window,
                "maximum_packet_size",
                "max_packet_size",
                default=0
            )
        ),

        "flows_per_second": safe_float(
            window.get("flows_per_second", 0.0)
        ),
        "packets_per_second": safe_float(
            window.get("packets_per_second", 0.0)
        ),
        "bytes_per_second": safe_float(
            window.get("bytes_per_second", 0.0)
        ),

        "forward_packet_ratio": safe_float(
            window.get("forward_packet_ratio", 0.0)
        ),
        "backward_packet_ratio": safe_float(
            window.get("backward_packet_ratio", 0.0)
        ),
        "forward_byte_ratio": safe_float(
            window.get("forward_byte_ratio", 0.0)
        ),
        "backward_byte_ratio": safe_float(
            window.get("backward_byte_ratio", 0.0)
        ),

        "unique_source_ips": safe_int(
            window.get("unique_source_ips", 0)
        ),
        "unique_destination_ips": safe_int(
            window.get("unique_destination_ips", 0)
        ),
        "unique_source_ports": safe_int(
            window.get("unique_source_ports", 0)
        ),
        "unique_destination_ports": safe_int(
            window.get("unique_destination_ports", 0)
        ),

        "max_connections_to_single_ip": safe_int(
            window.get("max_connections_to_single_ip", 0)
        ),
        "max_connections_to_single_port": safe_int(
            window.get("max_connections_to_single_port", 0)
        ),

        "tcp_flow_count": tcp_flows,
        "udp_flow_count": udp_flows,
        "icmp_flow_count": icmp_flows,

        "syn_count": safe_int(window.get("syn_count", 0)),
        "ack_count": safe_int(window.get("ack_count", 0)),
        "fin_count": safe_int(window.get("fin_count", 0)),
        "rst_count": safe_int(window.get("rst_count", 0)),
        "psh_count": safe_int(window.get("psh_count", 0)),
        "urg_count": urgent,

        "syn_packet_ratio": safe_float(
            window.get("syn_packet_ratio", 0.0)
        ),
        "rst_packet_ratio": safe_float(
            window.get("rst_packet_ratio", 0.0)
        ),
        "syn_ack_ratio": safe_float(
            window.get("syn_ack_ratio", 0.0)
        ),

        "single_packet_flow_count": safe_int(
            window.get("single_packet_flow_count", 0)
        ),
        "rst_flow_count": rst_flow_count,
        "syn_flow_count": syn_flow_count,

        "single_packet_flow_ratio": safe_float(
            window.get("single_packet_flow_ratio", 0.0)
        ),
        "rst_flow_ratio": safe_float(
            window.get("rst_flow_ratio", 0.0)
        ),
        "syn_flow_ratio": safe_float(
            window.get("syn_flow_ratio", 0.0)
        ),

        "syn_rate": safe_float(window.get("syn_rate", 0.0)),
        "rst_rate": safe_float(window.get("rst_rate", 0.0)),

        "https_flow_count": safe_int(
            window.get("https_flow_count", 0)
        ),
        "http_flow_count": safe_int(
            window.get("http_flow_count", 0)
        ),
        "dns_flow_count": safe_int(
            window.get("dns_flow_count", 0)
        ),
        "ssh_flow_count": safe_int(
            window.get("ssh_flow_count", 0)
        ),
        "rdp_flow_count": safe_int(
            window.get("rdp_flow_count", 0)
        ),
        "smb_flow_count": safe_int(
            window.get("smb_flow_count", 0)
        ),

        "service_distribution": service_counts,
    }

    return {
        "window_start": window.get("window_start"),
        "window_end": window.get("window_end"),

        # ----------------------------------------------------------
        # NSL-KDD-compatible / inspired fields
        # ----------------------------------------------------------
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,

        # ----------------------------------------------------------
        # Additional telemetry
        # ----------------------------------------------------------
        "additional_network_features": additional_features,

        "feature_source": "network_behaviour",
        "mapping_version": "3.0",
        "mapping_status": "PARTIAL_NSL_KDD_COMPATIBLE",
    }


def read_jsonl(filename):
    records = []

    if not os.path.exists(filename):
        print(f"[ERROR] Input file not found: {filename}")
        return records

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    print(
                        f"[WARNING] Invalid JSON on line "
                        f"{line_number}; skipped."
                    )

    except Exception as error:
        print(f"[ERROR] Could not read input: {error}")

    return records


def process():
    print("==========================================")
    print("      NETWORK FEATURE MAPPER")
    print("==========================================")
    print(f"Input file  : {INPUT_FILE}")
    print(f"Output file : {OUTPUT_FILE}")
    print("Features    : NSL-KDD + network telemetry")
    print("------------------------------------------")

    windows = read_jsonl(INPUT_FILE)

    if not windows:
        print("[ERROR] No network behaviour windows found.")
        return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    processed = 0
    unknown_protocols = 0
    unknown_services = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output:
        for window in windows:
            mapped = map_window(window)

            if mapped["protocol_type"] == "unknown":
                unknown_protocols += 1

            if mapped["service"] == "unknown":
                unknown_services += 1

            output.write(
                json.dumps(mapped, ensure_ascii=False)
                + "\n"
            )

            processed += 1

    print(f"[INFO] Windows processed: {processed}")
    print(f"[INFO] Unknown protocols : {unknown_protocols}")
    print(f"[INFO] Unknown services  : {unknown_services}")
    print("------------------------------------------")
    print("Network feature mapping completed.")
    print(f"Output: {OUTPUT_FILE}")
    print("==========================================")


if __name__ == "__main__":
    process()
