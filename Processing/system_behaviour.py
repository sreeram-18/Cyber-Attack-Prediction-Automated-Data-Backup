"""
system_behaviour.py

Combines:
    - Windows Security/System event logs
    - System resource snapshots

into fixed time-based behaviour windows.

Input:
    Collectors/event_logs.jsonl
    Collectors/system_events.jsonl

Output:
    Processing/system_windows.jsonl
"""

import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

EVENT_LOG_FILE = os.path.join(
    BASE_DIR,
    "Collectors",
    "event_logs.jsonl"
)

SYSTEM_FILE = os.path.join(
    BASE_DIR,
    "Collectors",
    "system_events.jsonl"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "Processing",
    "system_windows.jsonl"
)

WINDOW_SIZE = 30


# ============================================================
# EVENT ID DEFINITIONS
# ============================================================

# Authentication
SUCCESSFUL_LOGON_IDS = {
    4624
}

FAILED_LOGON_IDS = {
    4625
}

LOGOFF_IDS = {
    4634,
    4647
}

# Privilege
PRIVILEGE_IDS = {
    4672
}

# Process creation
PROCESS_CREATION_IDS = {
    4688
}

# Account management
ACCOUNT_CREATION_IDS = {
    4720
}

ACCOUNT_DELETION_IDS = {
    4726
}

# Group membership / group changes
GROUP_CHANGE_IDS = {
    4728,
    4729,
    4732,
    4733,
    4756,
    4757
}

# Windows service installation
SERVICE_INSTALLATION_IDS = {
    4697
}


# ============================================================
# HELPERS
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


def safe_rate(numerator, denominator):

    if denominator <= 0:
        return 0.0

    return numerator / denominator


def parse_timestamp(value):

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    value = str(value).strip()

    try:

        # Windows event timestamps commonly end with Z
        if value.endswith("Z"):

            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(
            value
        )

        if dt.tzinfo is None:

            dt = dt.replace(
                tzinfo=timezone.utc
            )

        return dt

    except Exception:

        return None


def get_event_id(record):

    possible_fields = [
        "event_id",
        "EventID",
        "eventId",
        "id"
    ]

    for field in possible_fields:

        if field in record:

            value = record[field]

            if isinstance(value, dict):

                value = value.get(
                    "id",
                    value.get(
                        "value"
                    )
                )

            try:

                return int(value)

            except (TypeError, ValueError):

                pass

    return None


def get_timestamp(record):

    possible_fields = [
        "timestamp",
        "time",
        "TimeCreated",
        "event_time",
        "datetime"
    ]

    for field in possible_fields:

        if field in record:

            parsed = parse_timestamp(
                record[field]
            )

            if parsed:
                return parsed

    return None


# ============================================================
# EVENT CLASSIFICATION
# ============================================================

def classify_event(record):

    event_id = get_event_id(record)

    # --------------------------------------------------------
    # First priority: Windows Event ID
    # --------------------------------------------------------

    if event_id in SUCCESSFUL_LOGON_IDS:
        return "successful_logon"

    if event_id in FAILED_LOGON_IDS:
        return "failed_logon"

    if event_id in LOGOFF_IDS:
        return "logoff"

    if event_id in PRIVILEGE_IDS:
        return "privilege"

    if event_id in PROCESS_CREATION_IDS:
        return "process_creation"

    if event_id in ACCOUNT_CREATION_IDS:
        return "account_creation"

    if event_id in ACCOUNT_DELETION_IDS:
        return "account_deletion"

    if event_id in GROUP_CHANGE_IDS:
        return "group_change"

    if event_id in SERVICE_INSTALLATION_IDS:
        return "service_installation"


    # --------------------------------------------------------
    # Fallback: event type text
    # --------------------------------------------------------

    possible_fields = [
        "event_type",
        "type",
        "EventType",
        "description",
        "message"
    ]

    event_text = ""

    for field in possible_fields:

        value = record.get(field)

        if value:

            event_text += " " + str(value).lower()


    # --------------------------------------------------------
    # Successful logon
    # --------------------------------------------------------

    if (
        "successful logon" in event_text
        or "successful login" in event_text
        or "logon success" in event_text
        or "login success" in event_text
    ):

        return "successful_logon"


    # --------------------------------------------------------
    # Failed logon
    # --------------------------------------------------------

    if (
        "failed logon" in event_text
        or "failed login" in event_text
        or "logon failure" in event_text
        or "login failure" in event_text
    ):

        return "failed_logon"


    # --------------------------------------------------------
    # Logoff
    # --------------------------------------------------------

    if (
        "logoff" in event_text
        or "logged off" in event_text
    ):

        return "logoff"


    # --------------------------------------------------------
    # Privilege
    # --------------------------------------------------------

    if (
        "special privileges" in event_text
        or "privilege" in event_text
    ):

        return "privilege"


    # --------------------------------------------------------
    # Process creation
    # --------------------------------------------------------

    if (
        "process creation" in event_text
        or "new process" in event_text
    ):

        return "process_creation"


    return "other"


# ============================================================
# EXTRACT EVENT INFORMATION
# ============================================================

def extract_user(record):

    possible_fields = [
        "user",
        "username",
        "User",
        "account_name",
        "AccountName",
        "target_user"
    ]

    for field in possible_fields:

        value = record.get(field)

        if value:

            value = str(value).strip()

            if value and value.lower() not in {
                "none",
                "null",
                "unknown"
            }:

                return value

    return None


def extract_source_ip(record):

    possible_fields = [
        "source_ip",
        "SourceIP",
        "src_ip",
        "source_address",
        "SourceAddress",
        "ip_address"
    ]

    for field in possible_fields:

        value = record.get(field)

        if value:

            value = str(value).strip()

            if value and value.lower() not in {
                "none",
                "null",
                "unknown"
            }:

                return value

    return None


# ============================================================
# READ JSONL
# ============================================================

def read_jsonl(filename):

    records = []

    if not os.path.exists(filename):

        print(
            f"[WARNING] File not found: {filename}"
        )

        return records

    try:

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:

                    record = json.loads(
                        line
                    )

                    if isinstance(
                        record,
                        dict
                    ):

                        records.append(
                            record
                        )

                except json.JSONDecodeError:

                    print(
                        "[WARNING] Invalid JSON "
                        "record skipped."
                    )

    except Exception as error:

        print(
            f"[ERROR] Could not read "
            f"{filename}: {error}"
        )

    return records


# ============================================================
# WINDOW KEY
# ============================================================

def get_window_start(timestamp):

    timestamp_seconds = timestamp.timestamp()

    window_seconds = (
        int(timestamp_seconds)
        // WINDOW_SIZE
    ) * WINDOW_SIZE

    return datetime.fromtimestamp(
        window_seconds,
        tz=timezone.utc
    )


# ============================================================
# CREATE EMPTY WINDOW
# ============================================================

def create_window(window_start):

    window_end = (
        window_start.timestamp()
        + WINDOW_SIZE
    )

    window_end = datetime.fromtimestamp(
        window_end,
        tz=timezone.utc
    )

    return {

        "window_start":
            window_start.isoformat(),

        "window_end":
            window_end.isoformat(),

        # ----------------------------------------------------
        # Event statistics
        # ----------------------------------------------------

        "event_record_count": 0,

        "successful_logins": 0,

        "num_failed_logins": 0,

        "logoff_count": 0,

        "privilege_event_count": 0,

        "process_creation_count": 0,

        "account_creation_count": 0,

        "account_deletion_count": 0,

        "group_change_count": 0,

        "service_installation_count": 0,

        # ----------------------------------------------------
        # Users / IPs
        # ----------------------------------------------------

        "users": set(),

        "source_ips": set(),

        # ----------------------------------------------------
        # System snapshots
        # ----------------------------------------------------

        "system_snapshot_count": 0,

        "cpu_values": [],

        "memory_values": [],

        "disk_values": [],

        "process_values": [],

        "high_cpu_process_values": [],

        "network_connection_values": [],

        "established_connection_values": [],

        "listening_connection_values": [],

        "active_user_values": []
    }


# ============================================================
# ADD EVENT TO WINDOW
# ============================================================

def add_event(window, record):

    window["event_record_count"] += 1

    event_id = get_event_id(
        record
    )

    event_type = classify_event(
        record
    )


    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if event_type == "successful_logon":

        window[
            "successful_logins"
        ] += 1


    elif event_type == "failed_logon":

        window[
            "num_failed_logins"
        ] += 1


    elif event_type == "logoff":

        window[
            "logoff_count"
        ] += 1


    # --------------------------------------------------------
    # Privilege
    # --------------------------------------------------------

    elif event_type == "privilege":

        window[
            "privilege_event_count"
        ] += 1


    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    elif event_type == "process_creation":

        window[
            "process_creation_count"
        ] += 1


    # --------------------------------------------------------
    # Account
    # --------------------------------------------------------

    elif event_type == "account_creation":

        window[
            "account_creation_count"
        ] += 1


    elif event_type == "account_deletion":

        window[
            "account_deletion_count"
        ] += 1


    # --------------------------------------------------------
    # Groups
    # --------------------------------------------------------

    elif event_type == "group_change":

        window[
            "group_change_count"
        ] += 1


    # --------------------------------------------------------
    # Services
    # --------------------------------------------------------

    elif event_type == "service_installation":

        window[
            "service_installation_count"
        ] += 1


    # --------------------------------------------------------
    # User
    # --------------------------------------------------------

    user = extract_user(
        record
    )

    if user:

        window[
            "users"
        ].add(user)


    # --------------------------------------------------------
    # Source IP
    # --------------------------------------------------------

    source_ip = extract_source_ip(
        record
    )

    if source_ip:

        window[
            "source_ips"
        ].add(source_ip)


# ============================================================
# EXTRACT SYSTEM SNAPSHOT VALUES
# ============================================================

def get_snapshot_value(
    record,
    possible_fields,
    default=0.0
):

    for field in possible_fields:

        if field in record:

            return safe_float(
                record[field],
                default
            )

    return default


def add_system_snapshot(
    window,
    record
):

    window[
        "system_snapshot_count"
    ] += 1


    # --------------------------------------------------------
    # CPU
    # --------------------------------------------------------

    cpu = get_snapshot_value(
        record,
        [
            "cpu_percent",
            "cpu_usage",
            "cpu",
            "CPU Usage"
        ]
    )

    window[
        "cpu_values"
    ].append(cpu)


    # --------------------------------------------------------
    # Memory
    # --------------------------------------------------------

    memory = get_snapshot_value(
        record,
        [
            "memory_percent",
            "memory_usage",
            "memory",
            "Memory Usage"
        ]
    )

    window[
        "memory_values"
    ].append(memory)


    # --------------------------------------------------------
    # Disk
    # --------------------------------------------------------

    disk = get_snapshot_value(
        record,
        [
            "disk_percent",
            "disk_usage",
            "disk",
            "Disk Usage"
        ]
    )

    window[
        "disk_values"
    ].append(disk)


    # --------------------------------------------------------
    # Processes
    # --------------------------------------------------------

    processes = get_snapshot_value(
        record,
        [
            "process_count",
            "processes",
            "Processes"
        ]
    )

    window[
        "process_values"
    ].append(processes)


    # --------------------------------------------------------
    # High CPU processes
    # --------------------------------------------------------

    high_cpu = get_snapshot_value(
        record,
        [
            "high_cpu_processes",
            "high_cpu",
            "High CPU"
        ]
    )

    window[
        "high_cpu_process_values"
    ].append(high_cpu)


    # --------------------------------------------------------
    # Network connections
    # --------------------------------------------------------

    connections = get_snapshot_value(
        record,
        [
            "network_connections",
            "network_conn",
            "connections",
            "Network Conn."
        ]
    )

    window[
        "network_connection_values"
    ].append(connections)


    # --------------------------------------------------------
    # Established
    # --------------------------------------------------------

    established = get_snapshot_value(
        record,
        [
            "established_connections",
            "established",
            "Established"
        ]
    )

    window[
        "established_connection_values"
    ].append(established)


    # --------------------------------------------------------
    # Listening
    # --------------------------------------------------------

    listening = get_snapshot_value(
        record,
        [
            "listening_connections",
            "listening",
            "Listening"
        ]
    )

    window[
        "listening_connection_values"
    ].append(listening)


    # --------------------------------------------------------
    # Active users
    # --------------------------------------------------------

    active_users = get_snapshot_value(
        record,
        [
            "active_users",
            "users",
            "Active Users"
        ]
    )

    window[
        "active_user_values"
    ].append(active_users)


# ============================================================
# AVERAGE
# ============================================================

def average(values):

    if not values:
        return 0.0

    return sum(values) / len(values)


def maximum(values):

    if not values:
        return 0.0

    return max(values)


# ============================================================
# FINALIZE WINDOW
# ============================================================

def finalize_window(window):

    snapshot_count = window[
        "system_snapshot_count"
    ]

    event_count = window[
        "event_record_count"
    ]


    # ========================================================
    # EVENT FEATURES
    # ========================================================

    failed_logins = window[
        "num_failed_logins"
    ]

    successful_logins = window[
        "successful_logins"
    ]

    privileges = window[
        "privilege_event_count"
    ]

    process_creation = window[
        "process_creation_count"
    ]


    # --------------------------------------------------------
    # Login state
    # --------------------------------------------------------

    logged_in = (
        1
        if successful_logins > 0
        else 0
    )


    # --------------------------------------------------------
    # Host login
    #
    # We consider a successful local logon as host login.
    # 127.0.0.1 is also treated as local.
    # --------------------------------------------------------

    is_host_login = 0

    if successful_logins > 0:

        is_host_login = 1


    # --------------------------------------------------------
    # Guest login
    #
    # Determined from captured usernames.
    # --------------------------------------------------------

    is_guest_login = 0

    for user in window["users"]:

        if user.lower() == "guest":

            is_guest_login = 1

            break


    # ========================================================
    # SYSTEM SNAPSHOT FEATURES
    # ========================================================

    cpu_values = window[
        "cpu_values"
    ]

    memory_values = window[
        "memory_values"
    ]

    disk_values = window[
        "disk_values"
    ]

    process_values = window[
        "process_values"
    ]

    high_cpu_values = window[
        "high_cpu_process_values"
    ]

    connection_values = window[
        "network_connection_values"
    ]

    established_values = window[
        "established_connection_values"
    ]

    listening_values = window[
        "listening_connection_values"
    ]

    active_user_values = window[
        "active_user_values"
    ]


    # ========================================================
    # DERIVED SECURITY RATES
    # ========================================================

    failed_login_rate = (
        safe_rate(
            failed_logins,
            event_count
        )
    )

    privilege_event_rate = (
        safe_rate(
            privileges,
            event_count
        )
    )

    process_creation_rate = (
        safe_rate(
            process_creation,
            event_count
        )
    )


    suspicious_event_count = (
        failed_logins
        + privileges
        + window["account_creation_count"]
        + window["account_deletion_count"]
        + window["group_change_count"]
        + window["service_installation_count"]
    )

    suspicious_event_rate = (
        safe_rate(
            suspicious_event_count,
            event_count
        )
    )


    # ========================================================
    # FINAL RECORD
    # ========================================================

    result = {

        # ----------------------------------------------------
        # Time
        # ----------------------------------------------------

        "window_start":
            window["window_start"],

        "window_end":
            window["window_end"],


        # ----------------------------------------------------
        # Event information
        # ----------------------------------------------------

        "event_record_count":
            event_count,

        "successful_logins":
            successful_logins,

        "num_failed_logins":
            failed_logins,

        "logoff_count":
            window["logoff_count"],

        "privilege_event_count":
            privileges,

        "process_creation_count":
            process_creation,

        "account_creation_count":
            window[
                "account_creation_count"
            ],

        "account_deletion_count":
            window[
                "account_deletion_count"
            ],

        "group_change_count":
            window[
                "group_change_count"
            ],

        "service_installation_count":
            window[
                "service_installation_count"
            ],


        # ----------------------------------------------------
        # User information
        # ----------------------------------------------------

        "unique_users":
            len(
                window["users"]
            ),

        "unique_source_ips":
            len(
                window["source_ips"]
            ),


        # ----------------------------------------------------
        # NSL-KDD-inspired system features
        # ----------------------------------------------------

        "logged_in":
            logged_in,

        "num_root":
            privileges,

        "is_host_login":
            is_host_login,

        "is_guest_login":
            is_guest_login,


        # ----------------------------------------------------
        # Snapshot count
        # ----------------------------------------------------

        "system_snapshot_count":
            snapshot_count,


        # ----------------------------------------------------
        # CPU
        # ----------------------------------------------------

        "avg_cpu_percent":
            average(cpu_values),

        "max_cpu_percent":
            maximum(cpu_values),


        # ----------------------------------------------------
        # Memory
        # ----------------------------------------------------

        "avg_memory_percent":
            average(memory_values),

        "max_memory_percent":
            maximum(memory_values),


        # ----------------------------------------------------
        # Disk
        # ----------------------------------------------------

        "avg_disk_percent":
            average(disk_values),

        "max_disk_percent":
            maximum(disk_values),


        # ----------------------------------------------------
        # Processes
        # ----------------------------------------------------

        "avg_process_count":
            average(process_values),

        "max_process_count":
            maximum(process_values),

        "avg_high_cpu_processes":
            average(high_cpu_values),

        "max_high_cpu_processes":
            maximum(high_cpu_values),


        # ----------------------------------------------------
        # Network connections
        # ----------------------------------------------------

        "avg_network_connections":
            average(connection_values),

        "max_network_connections":
            maximum(connection_values),

        "avg_established_connections":
            average(established_values),

        "max_established_connections":
            maximum(established_values),

        "avg_listening_connections":
            average(listening_values),

        "max_listening_connections":
            maximum(listening_values),


        # ----------------------------------------------------
        # Active users
        # ----------------------------------------------------

        "avg_active_users":
            average(active_user_values),


        # ----------------------------------------------------
        # Derived security metrics
        # ----------------------------------------------------

        "failed_login_rate":
            failed_login_rate,

        "privilege_event_rate":
            privilege_event_rate,

        "process_creation_rate":
            process_creation_rate,

        "suspicious_event_count":
            suspicious_event_count,

        "suspicious_event_rate":
            suspicious_event_rate
    }


    # ========================================================
    # EXTRA DIAGNOSTIC INFORMATION
    # ========================================================

    result[
        "system_snapshot_available"
    ] = snapshot_count > 0

    return result


# ============================================================
# MAIN PROCESSOR
# ============================================================

def process():

    print("==========================================")
    print("       SYSTEM BEHAVIOUR PROCESSOR")
    print("==========================================")

    print(
        f"Event log file : {EVENT_LOG_FILE}"
    )

    print(
        f"System file    : {SYSTEM_FILE}"
    )

    print(
        f"Output file    : {OUTPUT_FILE}"
    )

    print(
        f"Window size    : {WINDOW_SIZE} seconds"
    )

    print("------------------------------------------")


    # ========================================================
    # LOAD DATA
    # ========================================================

    event_records = read_jsonl(
        EVENT_LOG_FILE
    )

    system_records = read_jsonl(
        SYSTEM_FILE
    )


    print(
        f"[INFO] Event records loaded: "
        f"{len(event_records)}"
    )

    print(
        f"[INFO] System snapshots loaded: "
        f"{len(system_records)}"
    )


    # ========================================================
    # WINDOWS
    # ========================================================

    windows = {}


    # ========================================================
    # PROCESS EVENTS
    # ========================================================

    for record in event_records:

        timestamp = get_timestamp(
            record
        )

        if timestamp is None:
            continue

        window_start = get_window_start(
            timestamp
        )

        key = window_start.isoformat()

        if key not in windows:

            windows[key] = create_window(
                window_start
            )

        add_event(
            windows[key],
            record
        )


    # ========================================================
    # PROCESS SYSTEM SNAPSHOTS
    # ========================================================

    for record in system_records:

        timestamp = get_timestamp(
            record
        )

        if timestamp is None:
            continue

        window_start = get_window_start(
            timestamp
        )

        key = window_start.isoformat()

        if key not in windows:

            windows[key] = create_window(
                window_start
            )

        add_system_snapshot(
            windows[key],
            record
        )


    # ========================================================
    # NO DATA
    # ========================================================

    if not windows:

        print(
            "[WARNING] No valid records found."
        )

        return


    # ========================================================
    # SORT WINDOWS
    # ========================================================

    sorted_windows = sorted(
        windows.values(),
        key=lambda item:
            item["window_start"]
    )


    # ========================================================
    # WRITE OUTPUT
    # ========================================================

    os.makedirs(
        os.path.dirname(
            OUTPUT_FILE
        ),
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as output:

        for window in sorted_windows:

            finalized = finalize_window(
                window
            )

            output.write(
                json.dumps(
                    finalized,
                    ensure_ascii=False
                )
                + "\n"
            )


    # ========================================================
    # SUMMARY
    # ========================================================

    snapshot_windows = sum(
        1
        for window in sorted_windows
        if window[
            "system_snapshot_count"
        ] > 0
    )

    event_only_windows = (
        len(sorted_windows)
        - snapshot_windows
    )

    total_failed_logins = sum(
        window[
            "num_failed_logins"
        ]
        for window in sorted_windows
    )

    total_successful_logins = sum(
        window[
            "successful_logins"
        ]
        for window in sorted_windows
    )


    print(
        f"[INFO] Behaviour windows created: "
        f"{len(sorted_windows)}"
    )

    print(
        f"[INFO] Windows with system "
        f"snapshots: {snapshot_windows}"
    )

    print(
        f"[INFO] Event-only windows: "
        f"{event_only_windows}"
    )

    print(
        f"[INFO] Successful logons counted: "
        f"{total_successful_logins}"
    )

    print(
        f"[INFO] Failed logons counted: "
        f"{total_failed_logins}"
    )

    print("------------------------------------------")

    print(
        f"[INFO] Output: {OUTPUT_FILE}"
    )

    print("------------------------------------------")

    print(
        "System behaviour processing completed."
    )

    print("==========================================")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    process()