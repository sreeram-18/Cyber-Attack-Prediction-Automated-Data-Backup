"""
feature_aggregator.py

Combines network ML features and system ML features into a common
30-second telemetry window.

Why 30 seconds?
- system_behaviour.py produces 30-second windows
- network_behaviour.py produces 10-second windows
- therefore network windows are re-bucketed into the same 30-second
  timeline before aggregation.

This avoids the old exact-timestamp matching problem.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NETWORK_FILE = os.path.join(
    BASE_DIR, "Processing", "ml_network_features.jsonl"
)

SYSTEM_FILE = os.path.join(
    BASE_DIR, "Processing", "system_ml_features.jsonl"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR, "Processing", "ml_features.jsonl"
)

UNIFIED_WINDOW_SECONDS = 30


# ------------------------------------------------------------------
# SAFE HELPERS
# ------------------------------------------------------------------

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


def parse_timestamp(value):
    if not value:
        return None

    try:
        value = str(value).strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        # The network collector currently emits naive timestamps.
        # Treat them as UTC so they can safely be combined with the
        # timezone-aware system timestamps.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except Exception:
        return None


def floor_to_window(dt, seconds=UNIFIED_WINDOW_SECONDS):
    timestamp = int(dt.timestamp())
    bucket = (timestamp // seconds) * seconds

    return datetime.fromtimestamp(
        bucket,
        tz=timezone.utc
    )


def read_jsonl(filename):
    records = []

    if not os.path.exists(filename):
        print(f"[WARNING] File not found: {filename}")
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
                        f"[WARNING] Invalid JSON in {filename}, "
                        f"line {line_number}; skipped."
                    )

    except Exception as error:
        print(f"[ERROR] Could not read {filename}: {error}")

    return records


# ------------------------------------------------------------------
# SYSTEM AGGREGATION
# ------------------------------------------------------------------

SYSTEM_SUM_FIELDS = [
    "num_failed_logins",
    "successful_logins",
    "failed_logins",
    "logoff_count",
    "privilege_event_count",
    "process_creation_count",
    "account_creation_count",
    "account_deletion_count",
    "group_change_count",
    "service_installation_count",
    "event_record_count",
    "system_snapshot_count",
]

SYSTEM_MAX_FIELDS = [
    "num_root",
    "is_host_login",
    "is_guest_login",
    "logged_in",
    "max_cpu_percent",
    "max_memory_percent",
    "max_disk_percent",
    "max_process_count",
    "max_high_cpu_processes",
    "max_network_connections",
    "max_established_connections",
    "max_listening_connections",
]


def aggregate_system_records(records, bucket_start):
    if not records:
        return empty_system(bucket_start)

    bucket_end = bucket_start.timestamp() + UNIFIED_WINDOW_SECONDS
    bucket_end = datetime.fromtimestamp(
        bucket_end,
        tz=timezone.utc
    )

    result = {
        "window_start": bucket_start.isoformat(),
        "window_end": bucket_end.isoformat(),
    }

    for field in SYSTEM_SUM_FIELDS:
        result[field] = sum(
            safe_int(record.get(field, 0))
            for record in records
        )

    for field in SYSTEM_MAX_FIELDS:
        result[field] = max(
            safe_float(record.get(field, 0))
            for record in records
        )

    # Values that represent averages should be weighted by the number
    # of snapshots when possible.
    average_fields = [
        "avg_cpu_percent",
        "avg_memory_percent",
        "avg_disk_percent",
        "avg_process_count",
        "avg_high_cpu_processes",
        "avg_network_connections",
        "avg_established_connections",
        "avg_listening_connections",
        "avg_active_users",
    ]

    total_weights = sum(
        max(1, safe_int(record.get("system_snapshot_count", 0)))
        for record in records
    )

    for field in average_fields:
        numerator = sum(
            safe_float(record.get(field, 0.0))
            * max(1, safe_int(
                record.get("system_snapshot_count", 0)
            ))
            for record in records
        )

        result[field] = (
            numerator / total_weights
            if total_weights > 0
            else 0.0
        )

    event_count = result["event_record_count"]

    result["failed_login_rate"] = (
        result["failed_logins"] / event_count
        if event_count > 0
        else 0.0
    )

    result["privilege_event_rate"] = (
        result["privilege_event_count"] / event_count
        if event_count > 0
        else 0.0
    )

    result["process_creation_rate"] = (
        result["process_creation_count"] / event_count
        if event_count > 0
        else 0.0
    )

    result["suspicious_event_count"] = sum(
        result[field]
        for field in [
            "failed_logins",
            "privilege_event_count",
            "account_creation_count",
            "account_deletion_count",
            "group_change_count",
            "service_installation_count",
        ]
    )

    result["suspicious_event_rate"] = (
        result["suspicious_event_count"] / event_count
        if event_count > 0
        else 0.0
    )

    avg_processes = result["avg_process_count"]

    result["high_cpu_ratio"] = (
        result["avg_high_cpu_processes"] / avg_processes
        if avg_processes > 0
        else 0.0
    )

    avg_connections = result["avg_network_connections"]

    result["established_connection_ratio"] = (
        result["avg_established_connections"]
        / avg_connections
        if avg_connections > 0
        else 0.0
    )

    result["listening_connection_ratio"] = (
        result["avg_listening_connections"]
        / avg_connections
        if avg_connections > 0
        else 0.0
    )

    result["unique_users"] = max(
        safe_int(record.get("unique_users", 0))
        for record in records
    )

    result["unique_source_ips"] = max(
        safe_int(record.get("unique_source_ips", 0))
        for record in records
    )

    result["feature_source"] = "system_behaviour"
    result["mapping_version"] = "3.0"
    result["mapping_status"] = "PARTIAL_NSL_KDD_COMPATIBLE"
    result["system_snapshot_available"] = (
        result["system_snapshot_count"] > 0
    )

    result["additional_system_features"] = {
        key: value
        for key, value in result.items()
        if key not in {
            "window_start",
            "window_end",
            "feature_source",
            "mapping_version",
            "mapping_status",
            "additional_system_features",
        }
    }

    return result


def empty_system(bucket_start):
    bucket_end = datetime.fromtimestamp(
        bucket_start.timestamp() + UNIFIED_WINDOW_SECONDS,
        tz=timezone.utc
    )

    fields = {}

    for field in SYSTEM_SUM_FIELDS:
        fields[field] = 0

    for field in SYSTEM_MAX_FIELDS:
        fields[field] = 0

    for field in [
        "avg_cpu_percent",
        "avg_memory_percent",
        "avg_disk_percent",
        "avg_process_count",
        "avg_high_cpu_processes",
        "avg_network_connections",
        "avg_established_connections",
        "avg_listening_connections",
        "avg_active_users",
        "failed_login_rate",
        "privilege_event_rate",
        "process_creation_rate",
        "suspicious_event_count",
        "suspicious_event_rate",
        "high_cpu_ratio",
        "established_connection_ratio",
        "listening_connection_ratio",
        "unique_users",
        "unique_source_ips",
    ]:
        fields[field] = 0.0 if "rate" in field or field.startswith(
            "avg_"
        ) else 0

    fields["window_start"] = bucket_start.isoformat()
    fields["window_end"] = bucket_end.isoformat()
    fields["feature_source"] = "system_behaviour"
    fields["mapping_version"] = "3.0"
    fields["mapping_status"] = "PARTIAL_NSL_KDD_COMPATIBLE"
    fields["system_snapshot_available"] = False
    fields["additional_system_features"] = {}

    return fields


# ------------------------------------------------------------------
# NETWORK AGGREGATION
# ------------------------------------------------------------------

NETWORK_SUM_FIELDS = [
    "src_bytes",
    "dst_bytes",
    "urgent",
    "count",
    "srv_count",
]

NETWORK_ADDITIONAL_SUM_FIELDS = [
    "flow_count",
    "total_packets",
    "total_bytes",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "tcp_flow_count",
    "udp_flow_count",
    "icmp_flow_count",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "single_packet_flow_count",
    "rst_flow_count",
    "syn_flow_count",
    "https_flow_count",
    "http_flow_count",
    "dns_flow_count",
    "ssh_flow_count",
    "rdp_flow_count",
    "smb_flow_count",
]


def weighted_average(records, field, weight_field="count"):
    numerator = 0.0
    denominator = 0.0

    for record in records:
        weight = safe_float(record.get(weight_field, 0))

        if weight <= 0:
            weight = 1.0

        numerator += safe_float(record.get(field, 0.0)) * weight
        denominator += weight

    return numerator / denominator if denominator > 0 else 0.0


def weighted_category(records, field):
    counter = Counter()

    for record in records:
        value = record.get(field)

        if value in (None, "", "unknown"):
            continue

        weight = safe_int(record.get("count", 0))

        if weight <= 0:
            weight = 1

        counter[str(value)] += weight

    return counter.most_common(1)[0][0] if counter else "unknown"


def aggregate_network_records(records, bucket_start):
    if not records:
        return empty_network(bucket_start)

    bucket_end = datetime.fromtimestamp(
        bucket_start.timestamp() + UNIFIED_WINDOW_SECONDS,
        tz=timezone.utc
    )

    result = {
        "window_start": bucket_start.isoformat(),
        "window_end": bucket_end.isoformat(),
    }

    for field in NETWORK_SUM_FIELDS:
        result[field] = sum(
            safe_int(record.get(field, 0))
            for record in records
        )

    # Categorical values are chosen by flow-weighted majority.
    result["protocol_type"] = weighted_category(
        records, "protocol_type"
    )
    result["service"] = weighted_category(
        records, "service"
    )
    result["flag"] = weighted_category(
        records, "flag"
    )

    result["duration"] = weighted_average(
        records, "duration"
    )

    # Preserve missing NSL-KDD fields as null instead of inventing them.
    for field in [
        "land",
        "wrong_fragment",
        "srv_serror_rate",
        "srv_rerror_rate",
        "srv_diff_host_rate",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    ]:
        result[field] = None

    result["serror_rate"] = weighted_average(
        records, "serror_rate"
    )
    result["rerror_rate"] = weighted_average(
        records, "rerror_rate"
    )
    result["same_srv_rate"] = weighted_average(
        records, "same_srv_rate"
    )
    result["diff_srv_rate"] = weighted_average(
        records, "diff_srv_rate"
    )

    additional_records = [
        record.get("additional_network_features", {})
        for record in records
    ]

    # Aggregate additional telemetry.
    additional = {}

    for field in NETWORK_ADDITIONAL_SUM_FIELDS:
        additional[field] = sum(
            safe_int(record.get("additional_network_features", {}).get(
                field, 0
            ))
            for record in records
        )

    # Weighted averages
    for field in [
        "avg_flow_duration",
        "avg_packets_per_flow",
        "avg_bytes_per_flow",
        "avg_packet_size",
        "flows_per_second",
        "packets_per_second",
        "bytes_per_second",
        "forward_packet_ratio",
        "backward_packet_ratio",
        "forward_byte_ratio",
        "backward_byte_ratio",
        "syn_packet_ratio",
        "rst_packet_ratio",
        "syn_ack_ratio",
        "single_packet_flow_ratio",
        "rst_flow_ratio",
        "syn_flow_ratio",
        "syn_rate",
        "rst_rate",
    ]:
        additional[field] = weighted_average_additional(
            records, field
        )

    # Min/max fields
    additional["minimum_packet_size"] = min(
        (
            safe_int(
                record.get(
                    "additional_network_features", {}
                ).get("minimum_packet_size", 0)
            )
            for record in records
            if safe_int(
                record.get(
                    "additional_network_features", {}
                ).get("minimum_packet_size", 0)
            ) > 0
        ),
        default=0
    )

    additional["maximum_packet_size"] = max(
        (
            safe_int(
                record.get(
                    "additional_network_features", {}
                ).get("maximum_packet_size", 0)
            )
            for record in records
        ),
        default=0
    )

    additional["window_duration"] = UNIFIED_WINDOW_SECONDS

    total_flows = additional["flow_count"]
    total_packets = additional["total_packets"]
    total_bytes = additional["total_bytes"]

    additional["flows_per_second"] = (
        total_flows / UNIFIED_WINDOW_SECONDS
    )
    additional["packets_per_second"] = (
        total_packets / UNIFIED_WINDOW_SECONDS
    )
    additional["bytes_per_second"] = (
        total_bytes / UNIFIED_WINDOW_SECONDS
    )

    additional["forward_packet_ratio"] = (
        additional["forward_packets"] / total_packets
        if total_packets > 0 else 0.0
    )
    additional["backward_packet_ratio"] = (
        additional["backward_packets"] / total_packets
        if total_packets > 0 else 0.0
    )
    additional["forward_byte_ratio"] = (
        additional["forward_bytes"] / total_bytes
        if total_bytes > 0 else 0.0
    )
    additional["backward_byte_ratio"] = (
        additional["backward_bytes"] / total_bytes
        if total_bytes > 0 else 0.0
    )

    additional["service_distribution"] = combine_service_distributions(
        records
    )

    additional["unique_source_ips"] = max(
        safe_int(record.get("additional_network_features", {}).get(
            "unique_source_ips", 0
        ))
        for record in records
    )

    additional["unique_destination_ips"] = max(
        safe_int(record.get("additional_network_features", {}).get(
            "unique_destination_ips", 0
        ))
        for record in records
    )

    additional["unique_source_ports"] = max(
        safe_int(record.get("additional_network_features", {}).get(
            "unique_source_ports", 0
        ))
        for record in records
    )

    additional["unique_destination_ports"] = max(
        safe_int(record.get("additional_network_features", {}).get(
            "unique_destination_ports", 0
        ))
        for record in records
    )

    for field in [
        "max_connections_to_single_ip",
        "max_connections_to_single_port",
    ]:
        additional[field] = max(
            safe_int(record.get("additional_network_features", {}).get(
                field, 0
            ))
            for record in records
        )

    result["additional_network_features"] = additional

    # Recalculate core NSL-style byte/count values from the aggregate.
    result["src_bytes"] = additional["forward_bytes"]
    result["dst_bytes"] = additional["backward_bytes"]
    result["count"] = additional["flow_count"]

    service_distribution = additional["service_distribution"]
    result["srv_count"] = (
        max(service_distribution.values())
        if service_distribution
        else 0
    )

    result["same_srv_rate"] = (
        result["srv_count"] / result["count"]
        if result["count"] > 0 else 0.0
    )
    result["diff_srv_rate"] = (
        1.0 - result["same_srv_rate"]
        if result["count"] > 0 else 0.0
    )

    result["serror_rate"] = (
        additional["syn_flow_count"] / result["count"]
        if result["count"] > 0 else 0.0
    )
    result["rerror_rate"] = (
        additional["rst_flow_count"] / result["count"]
        if result["count"] > 0 else 0.0
    )

    result["dst_host_count"] = additional["unique_destination_ips"]

    result["feature_source"] = "network_behaviour"
    result["mapping_version"] = "3.0"
    result["mapping_status"] = "PARTIAL_NSL_KDD_COMPATIBLE"

    return result


def weighted_average_additional(records, field):
    numerator = 0.0
    denominator = 0.0

    for record in records:
        additional = record.get(
            "additional_network_features", {}
        )

        weight = safe_float(
            additional.get("flow_count", record.get("count", 0))
        )

        if weight <= 0:
            weight = 1.0

        numerator += safe_float(
            additional.get(field, 0.0)
        ) * weight

        denominator += weight

    return numerator / denominator if denominator > 0 else 0.0


def combine_service_distributions(records):
    result = Counter()

    for record in records:
        distribution = record.get(
            "additional_network_features", {}
        ).get("service_distribution", {})

        if isinstance(distribution, dict):
            for service, count in distribution.items():
                result[str(service)] += safe_int(count)

    return dict(result)


def empty_network(bucket_start):
    bucket_end = datetime.fromtimestamp(
        bucket_start.timestamp() + UNIFIED_WINDOW_SECONDS,
        tz=timezone.utc
    )

    return {
        "window_start": bucket_start.isoformat(),
        "window_end": bucket_end.isoformat(),
        "duration": 0.0,
        "protocol_type": "unknown",
        "service": "unknown",
        "flag": "OTH",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": None,
        "wrong_fragment": None,
        "urgent": 0,
        "count": 0,
        "srv_count": 0,
        "serror_rate": 0.0,
        "srv_serror_rate": None,
        "rerror_rate": 0.0,
        "srv_rerror_rate": None,
        "same_srv_rate": 0.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": None,
        "dst_host_count": 0,
        "dst_host_srv_count": None,
        "dst_host_same_srv_rate": None,
        "dst_host_diff_srv_rate": None,
        "dst_host_same_src_port_rate": None,
        "dst_host_srv_diff_host_rate": None,
        "dst_host_serror_rate": None,
        "dst_host_srv_serror_rate": None,
        "dst_host_rerror_rate": None,
        "dst_host_srv_rerror_rate": None,
        "additional_network_features": {
            "flow_count": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "forward_packets": 0,
            "backward_packets": 0,
            "forward_bytes": 0,
            "backward_bytes": 0,
            "tcp_flow_count": 0,
            "udp_flow_count": 0,
            "icmp_flow_count": 0,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0,
            "urg_count": 0,
            "single_packet_flow_count": 0,
            "rst_flow_count": 0,
            "syn_flow_count": 0,
            "https_flow_count": 0,
            "http_flow_count": 0,
            "dns_flow_count": 0,
            "ssh_flow_count": 0,
            "rdp_flow_count": 0,
            "smb_flow_count": 0,
            "service_distribution": {},
            "window_duration": UNIFIED_WINDOW_SECONDS,
        },
        "feature_source": "network_behaviour",
        "mapping_version": "3.0",
        "mapping_status": "PARTIAL_NSL_KDD_COMPATIBLE",
    }


# ------------------------------------------------------------------
# UNIFIED RECORD
# ------------------------------------------------------------------

def create_unified_record(bucket_start, network, system):
    bucket_end = datetime.fromtimestamp(
        bucket_start.timestamp() + UNIFIED_WINDOW_SECONDS,
        tz=timezone.utc
    )

    network_present = network is not None
    system_present = system is not None

    if network is None:
        network = empty_network(bucket_start)

    if system is None:
        system = empty_system(bucket_start)

    network_features = {
        key: value
        for key, value in network.items()
        if key not in {
            "window_start",
            "window_end",
            "additional_network_features",
            "feature_source",
            "mapping_version",
            "mapping_status",
        }
    }

    system_features = {
        key: value
        for key, value in system.items()
        if key not in {
            "window_start",
            "window_end",
            "additional_system_features",
            "feature_source",
            "mapping_version",
            "mapping_status",
        }
    }

    total_security_events = (
        safe_int(system_features["failed_logins"])
        + safe_int(system_features["privilege_event_count"])
        + safe_int(system_features["process_creation_count"])
        + safe_int(system_features["account_creation_count"])
        + safe_int(system_features["account_deletion_count"])
        + safe_int(system_features["group_change_count"])
        + safe_int(system_features["service_installation_count"])
    )

    total_network_connections = (
        safe_int(
            network_features.get(
                "count", 0
            )
        )
    )

    authentication_pressure = (
        safe_int(system_features["failed_logins"])
        + safe_int(system_features["successful_logins"])
    )

    resource_pressure = max(
        safe_float(system_features["max_cpu_percent"]),
        safe_float(system_features["max_memory_percent"]),
        safe_float(system_features["max_disk_percent"]),
    )

    return {
        "window_start": bucket_start.isoformat(),
        "window_end": bucket_end.isoformat(),

        "network": {
            **network_features,
            "additional_network_features":
                network.get("additional_network_features", {}),
        },

        "system": {
            **system_features,
            "additional_system_features":
                system.get("additional_system_features", {}),
        },

        "combined": {
            "total_security_events": total_security_events,
            "network_activity_level": total_network_connections,
            "network_connection_pressure": (
                network.get(
                    "additional_network_features", {}
                ).get("tcp_flow_count", 0)
                + network.get(
                    "additional_network_features", {}
                ).get("udp_flow_count", 0)
                + network.get(
                    "additional_network_features", {}
                ).get("icmp_flow_count", 0)
            ),
            "authentication_pressure": authentication_pressure,
            "privilege_pressure": safe_int(
                system_features["privilege_event_count"]
            ),
            "process_activity": safe_int(
                system_features["process_creation_count"]
            ),
            "resource_pressure": resource_pressure,
        },

        "data_presence": {
            "network_available": network_present,
            "system_available": system_present,
            "both_available": network_present and system_present,
        },

        "feature_source": "network_and_system",
        "aggregation_version": "2.0",
        "aggregation_window_seconds": UNIFIED_WINDOW_SECONDS,
    }


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------

def process():
    print("==========================================")
    print("        FEATURE AGGREGATOR")
    print("==========================================")
    print(f"Network input : {NETWORK_FILE}")
    print(f"System input  : {SYSTEM_FILE}")
    print(f"Output file   : {OUTPUT_FILE}")
    print(f"Unified window: {UNIFIED_WINDOW_SECONDS} seconds")
    print("------------------------------------------")

    network_records = read_jsonl(NETWORK_FILE)
    system_records = read_jsonl(SYSTEM_FILE)

    print(
        f"[INFO] Network records loaded: "
        f"{len(network_records)}"
    )
    print(
        f"[INFO] System records loaded: "
        f"{len(system_records)}"
    )

    network_buckets = {}
    system_buckets = {}

    invalid_network = 0
    invalid_system = 0

    # --------------------------------------------------------------
    # Bucket network records into 30-second windows
    # --------------------------------------------------------------

    for record in network_records:
        timestamp = parse_timestamp(
            record.get("window_start")
        )

        if timestamp is None:
            invalid_network += 1
            continue

        bucket = floor_to_window(timestamp)

        network_buckets.setdefault(bucket, []).append(record)

    # --------------------------------------------------------------
    # Bucket system records into 30-second windows
    # --------------------------------------------------------------

    for record in system_records:
        timestamp = parse_timestamp(
            record.get("window_start")
        )

        if timestamp is None:
            invalid_system += 1
            continue

        bucket = floor_to_window(timestamp)

        system_buckets.setdefault(bucket, []).append(record)

    all_buckets = sorted(
        set(network_buckets) | set(system_buckets)
    )

    if not all_buckets:
        print("[WARNING] No valid time windows found.")
        return

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    matched = 0
    network_only = 0
    system_only = 0

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as output:

        for bucket in all_buckets:
            network_list = network_buckets.get(bucket, [])
            system_list = system_buckets.get(bucket, [])

            network = (
                aggregate_network_records(
                    network_list,
                    bucket
                )
                if network_list
                else None
            )

            system = (
                aggregate_system_records(
                    system_list,
                    bucket
                )
                if system_list
                else None
            )

            if network_list and system_list:
                matched += 1
            elif network_list:
                network_only += 1
            else:
                system_only += 1

            unified = create_unified_record(
                bucket,
                network,
                system
            )

            output.write(
                json.dumps(
                    unified,
                    ensure_ascii=False
                )
                + "\n"
            )

    print("------------------------------------------")
    print(f"[INFO] Unified 30-second windows: {len(all_buckets)}")
    print(f"[INFO] Matched network + system   : {matched}")
    print(f"[INFO] Network-only windows       : {network_only}")
    print(f"[INFO] System-only windows        : {system_only}")

    if invalid_network:
        print(
            f"[WARNING] Invalid network timestamps: "
            f"{invalid_network}"
        )

    if invalid_system:
        print(
            f"[WARNING] Invalid system timestamps: "
            f"{invalid_system}"
        )

    print("------------------------------------------")
    print("Feature aggregation completed.")
    print(f"Output: {OUTPUT_FILE}")
    print("==========================================")


if __name__ == "__main__":
    process()
