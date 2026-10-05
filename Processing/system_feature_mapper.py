"""
system_feature_mapper.py

Maps system behaviour windows into ML-ready system features.

Input:
    Processing/system_windows.jsonl

Output:
    Processing/system_ml_features.jsonl

The mapper:
    - Preserves security/event features
    - Preserves system resource telemetry
    - Adds derived security rates
    - Does NOT fabricate missing system measurements
    - Keeps NSL-KDD-inspired features separate from
      additional Windows telemetry
"""

import json
import os


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "Processing",
    "system_windows.jsonl"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "Processing",
    "system_ml_features.jsonl"
)


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


def clamp(value, minimum=0.0, maximum=1.0):

    return max(
        minimum,
        min(maximum, value)
    )


def get_first_value(
    data,
    fields,
    default=None
):

    """
    Return the first existing field from a list.

    This allows the mapper to support both current
    and older field names without silently losing data.
    """

    for field in fields:

        if field in data:

            return data[field]

    return default


# ============================================================
# MAP ONE SYSTEM WINDOW
# ============================================================

def map_window(window):

    # ========================================================
    # WINDOW INFORMATION
    # ========================================================

    window_start = window.get(
        "window_start"
    )

    window_end = window.get(
        "window_end"
    )


    # ========================================================
    # EVENT COUNTS
    # ========================================================

    event_record_count = safe_int(
        get_first_value(
            window,
            [
                "event_record_count"
            ],
            0
        )
    )


    # --------------------------------------------------------
    # IMPORTANT:
    #
    # system_windows.jsonl already contains:
    #
    #     successful_logins
    #
    # Do NOT only look for num_successful_logins.
    # --------------------------------------------------------

    successful_logins = safe_int(
        get_first_value(
            window,
            [
                "successful_logins",
                "num_successful_logins"
            ],
            0
        )
    )


    failed_logins = safe_int(
        get_first_value(
            window,
            [
                "num_failed_logins",
                "failed_logins"
            ],
            0
        )
    )


    logoff_count = safe_int(
        get_first_value(
            window,
            [
                "logoff_count"
            ],
            0
        )
    )


    privilege_event_count = safe_int(
        get_first_value(
            window,
            [
                "privilege_event_count"
            ],
            0
        )
    )


    process_creation_count = safe_int(
        get_first_value(
            window,
            [
                "process_creation_count"
            ],
            0
        )
    )


    account_creation_count = safe_int(
        get_first_value(
            window,
            [
                "account_creation_count"
            ],
            0
        )
    )


    account_deletion_count = safe_int(
        get_first_value(
            window,
            [
                "account_deletion_count"
            ],
            0
        )
    )


    group_change_count = safe_int(
        get_first_value(
            window,
            [
                "group_change_count"
            ],
            0
        )
    )


    service_installation_count = safe_int(
        get_first_value(
            window,
            [
                "service_installation_count"
            ],
            0
        )
    )


    # ========================================================
    # USER / IP INFORMATION
    # ========================================================

    unique_users = safe_int(
        get_first_value(
            window,
            [
                "unique_users"
            ],
            0
        )
    )


    unique_source_ips = safe_int(
        get_first_value(
            window,
            [
                "unique_source_ips"
            ],
            0
        )
    )


    # ========================================================
    # LOGIN FEATURES
    # ========================================================

    # Prefer the already-calculated value from
    # system_behaviour.py.

    logged_in_value = window.get(
        "logged_in"
    )

    if logged_in_value is not None:

        logged_in = safe_int(
            logged_in_value
        )

    else:

        logged_in = (
            1
            if successful_logins > 0
            else 0
        )


    # ========================================================
    # PRIVILEGE / ROOT ACTIVITY
    # ========================================================

    num_root = safe_int(
        get_first_value(
            window,
            [
                "num_root",
                "privilege_event_count"
            ],
            0
        )
    )


    # ========================================================
    # HOST LOGIN
    # ========================================================

    is_host_login = safe_int(
        get_first_value(
            window,
            [
                "is_host_login"
            ],
            0
        )
    )


    # ========================================================
    # GUEST LOGIN
    # ========================================================

    is_guest_login = safe_int(
        get_first_value(
            window,
            [
                "is_guest_login"
            ],
            0
        )
    )


    # ========================================================
    # SYSTEM SNAPSHOTS
    # ========================================================

    system_snapshot_count = safe_int(
        get_first_value(
            window,
            [
                "system_snapshot_count"
            ],
            0
        )
    )


    system_snapshot_available = (
        system_snapshot_count > 0
    )


    # ========================================================
    # CPU
    # ========================================================

    avg_cpu_percent = safe_float(
        get_first_value(
            window,
            [
                "avg_cpu_percent"
            ],
            0.0
        )
    )


    max_cpu_percent = safe_float(
        get_first_value(
            window,
            [
                "max_cpu_percent"
            ],
            0.0
        )
    )


    # ========================================================
    # MEMORY
    # ========================================================

    avg_memory_percent = safe_float(
        get_first_value(
            window,
            [
                "avg_memory_percent"
            ],
            0.0
        )
    )


    max_memory_percent = safe_float(
        get_first_value(
            window,
            [
                "max_memory_percent"
            ],
            0.0
        )
    )


    # ========================================================
    # DISK
    # ========================================================

    avg_disk_percent = safe_float(
        get_first_value(
            window,
            [
                "avg_disk_percent"
            ],
            0.0
        )
    )


    max_disk_percent = safe_float(
        get_first_value(
            window,
            [
                "max_disk_percent"
            ],
            0.0
        )
    )


    # ========================================================
    # PROCESS INFORMATION
    # ========================================================

    avg_process_count = safe_float(
        get_first_value(
            window,
            [
                "avg_process_count"
            ],
            0.0
        )
    )


    max_process_count = safe_float(
        get_first_value(
            window,
            [
                "max_process_count"
            ],
            0.0
        )
    )


    avg_high_cpu_processes = safe_float(
        get_first_value(
            window,
            [
                "avg_high_cpu_processes"
            ],
            0.0
        )
    )


    max_high_cpu_processes = safe_float(
        get_first_value(
            window,
            [
                "max_high_cpu_processes"
            ],
            0.0
        )
    )


    # ========================================================
    # NETWORK CONNECTIONS
    # ========================================================

    avg_network_connections = safe_float(
        get_first_value(
            window,
            [
                "avg_network_connections"
            ],
            0.0
        )
    )


    max_network_connections = safe_float(
        get_first_value(
            window,
            [
                "max_network_connections"
            ],
            0.0
        )
    )


    avg_established_connections = safe_float(
        get_first_value(
            window,
            [
                "avg_established_connections"
            ],
            0.0
        )
    )


    max_established_connections = safe_float(
        get_first_value(
            window,
            [
                "max_established_connections"
            ],
            0.0
        )
    )


    avg_listening_connections = safe_float(
        get_first_value(
            window,
            [
                "avg_listening_connections"
            ],
            0.0
        )
    )


    max_listening_connections = safe_float(
        get_first_value(
            window,
            [
                "max_listening_connections"
            ],
            0.0
        )
    )


    avg_active_users = safe_float(
        get_first_value(
            window,
            [
                "avg_active_users"
            ],
            0.0
        )
    )


    # ========================================================
    # DERIVED SECURITY FEATURES
    # ========================================================

    failed_login_rate = clamp(
        safe_rate(
            failed_logins,
            event_record_count
        )
    )


    privilege_event_rate = clamp(
        safe_rate(
            privilege_event_count,
            event_record_count
        )
    )


    process_creation_rate = clamp(
        safe_rate(
            process_creation_count,
            event_record_count
        )
    )


    # --------------------------------------------------------
    # Suspicious event activity
    # --------------------------------------------------------

    suspicious_event_count = (
        failed_logins
        + privilege_event_count
        + account_creation_count
        + account_deletion_count
        + group_change_count
        + service_installation_count
    )


    suspicious_event_rate = clamp(
        safe_rate(
            suspicious_event_count,
            event_record_count
        )
    )


    # --------------------------------------------------------
    # High CPU process ratio
    # --------------------------------------------------------

    high_cpu_ratio = clamp(
        safe_rate(
            avg_high_cpu_processes,
            avg_process_count
        )
    )


    # --------------------------------------------------------
    # Established connection ratio
    # --------------------------------------------------------

    established_connection_ratio = clamp(
        safe_rate(
            avg_established_connections,
            avg_network_connections
        )
    )


    # --------------------------------------------------------
    # Listening connection ratio
    # --------------------------------------------------------

    listening_connection_ratio = clamp(
        safe_rate(
            avg_listening_connections,
            avg_network_connections
        )
    )


    # ========================================================
    # ADDITIONAL SYSTEM FEATURES
    # ========================================================

    additional_system_features = {

        # ----------------------------------------------------
        # Event statistics
        # ----------------------------------------------------

        "event_record_count":
            event_record_count,

        "system_snapshot_count":
            system_snapshot_count,

        "successful_logins":
            successful_logins,

        "failed_logins":
            failed_logins,

        "logoff_count":
            logoff_count,

        "privilege_event_count":
            privilege_event_count,

        "process_creation_count":
            process_creation_count,

        "account_creation_count":
            account_creation_count,

        "account_deletion_count":
            account_deletion_count,

        "group_change_count":
            group_change_count,

        "service_installation_count":
            service_installation_count,


        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "unique_users":
            unique_users,

        "unique_source_ips":
            unique_source_ips,

        "logged_in":
            logged_in,


        # ----------------------------------------------------
        # Security rates
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
            suspicious_event_rate,


        # ----------------------------------------------------
        # CPU
        # ----------------------------------------------------

        "avg_cpu_percent":
            avg_cpu_percent,

        "max_cpu_percent":
            max_cpu_percent,


        # ----------------------------------------------------
        # Memory
        # ----------------------------------------------------

        "avg_memory_percent":
            avg_memory_percent,

        "max_memory_percent":
            max_memory_percent,


        # ----------------------------------------------------
        # Disk
        # ----------------------------------------------------

        "avg_disk_percent":
            avg_disk_percent,

        "max_disk_percent":
            max_disk_percent,


        # ----------------------------------------------------
        # Processes
        # ----------------------------------------------------

        "avg_process_count":
            avg_process_count,

        "max_process_count":
            max_process_count,

        "avg_high_cpu_processes":
            avg_high_cpu_processes,

        "max_high_cpu_processes":
            max_high_cpu_processes,

        "high_cpu_ratio":
            high_cpu_ratio,


        # ----------------------------------------------------
        # Network
        # ----------------------------------------------------

        "avg_network_connections":
            avg_network_connections,

        "max_network_connections":
            max_network_connections,

        "avg_established_connections":
            avg_established_connections,

        "max_established_connections":
            max_established_connections,

        "avg_listening_connections":
            avg_listening_connections,

        "max_listening_connections":
            max_listening_connections,

        "established_connection_ratio":
            established_connection_ratio,

        "listening_connection_ratio":
            listening_connection_ratio,


        # ----------------------------------------------------
        # Active users
        # ----------------------------------------------------

        "avg_active_users":
            avg_active_users
    }


    # ========================================================
    # FINAL ML RECORD
    # ========================================================

    result = {

        # ----------------------------------------------------
        # Window metadata
        # ----------------------------------------------------

        "window_start":
            window_start,

        "window_end":
            window_end,


        # ====================================================
        # NSL-KDD-INSPIRED / COMPATIBLE FEATURES
        # ====================================================

        "num_failed_logins":
            failed_logins,

        "logged_in":
            logged_in,

        "num_root":
            num_root,

        "is_host_login":
            is_host_login,

        "is_guest_login":
            is_guest_login,


        # ====================================================
        # AUTHENTICATION FEATURES
        # ====================================================

        "successful_logins":
            successful_logins,

        "failed_logins":
            failed_logins,

        "logoff_count":
            logoff_count,

        "unique_users":
            unique_users,

        "unique_source_ips":
            unique_source_ips,


        # ====================================================
        # SECURITY EVENT FEATURES
        # ====================================================

        "event_record_count":
            event_record_count,

        "system_snapshot_count":
            system_snapshot_count,

        "privilege_event_count":
            privilege_event_count,

        "process_creation_count":
            process_creation_count,

        "account_creation_count":
            account_creation_count,

        "account_deletion_count":
            account_deletion_count,

        "group_change_count":
            group_change_count,

        "service_installation_count":
            service_installation_count,


        # ====================================================
        # SYSTEM RESOURCE FEATURES
        # ====================================================

        "avg_cpu_percent":
            avg_cpu_percent,

        "max_cpu_percent":
            max_cpu_percent,

        "avg_memory_percent":
            avg_memory_percent,

        "max_memory_percent":
            max_memory_percent,

        "avg_disk_percent":
            avg_disk_percent,

        "max_disk_percent":
            max_disk_percent,


        # ====================================================
        # PROCESS FEATURES
        # ====================================================

        "avg_process_count":
            avg_process_count,

        "max_process_count":
            max_process_count,

        "avg_high_cpu_processes":
            avg_high_cpu_processes,

        "max_high_cpu_processes":
            max_high_cpu_processes,


        # ====================================================
        # NETWORK CONNECTION FEATURES
        # ====================================================

        "avg_network_connections":
            avg_network_connections,

        "max_network_connections":
            max_network_connections,

        "avg_established_connections":
            avg_established_connections,

        "max_established_connections":
            max_established_connections,

        "avg_listening_connections":
            avg_listening_connections,

        "max_listening_connections":
            max_listening_connections,

        "avg_active_users":
            avg_active_users,


        # ====================================================
        # DERIVED SECURITY FEATURES
        # ====================================================

        "failed_login_rate":
            failed_login_rate,

        "privilege_event_rate":
            privilege_event_rate,

        "process_creation_rate":
            process_creation_rate,

        "suspicious_event_count":
            suspicious_event_count,

        "suspicious_event_rate":
            suspicious_event_rate,

        "high_cpu_ratio":
            high_cpu_ratio,

        "established_connection_ratio":
            established_connection_ratio,

        "listening_connection_ratio":
            listening_connection_ratio,


        # ====================================================
        # ADDITIONAL TELEMETRY
        # ====================================================

        "additional_system_features":
            additional_system_features,


        # ====================================================
        # METADATA
        # ====================================================

        "feature_source":
            "system_behaviour",

        "mapping_version":
            "3.0",

        "mapping_status":
            "PARTIAL_NSL_KDD_COMPATIBLE",

        "system_snapshot_available":
            system_snapshot_available
    }


    return result


# ============================================================
# PROCESS FILE
# ============================================================

def process():

    print("==========================================")
    print("       SYSTEM FEATURE MAPPER")
    print("==========================================")

    print(
        f"Input file  : {INPUT_FILE}"
    )

    print(
        f"Output file : {OUTPUT_FILE}"
    )

    print(
        "Features    : NSL-KDD + system telemetry"
    )

    print("------------------------------------------")


    # ========================================================
    # CHECK INPUT
    # ========================================================

    if not os.path.exists(INPUT_FILE):

        print(
            "[ERROR] Input file not found:"
        )

        print(INPUT_FILE)

        return


    # ========================================================
    # LOAD WINDOWS
    # ========================================================

    windows = []

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:

                    window = json.loads(
                        line
                    )

                    if isinstance(
                        window,
                        dict
                    ):

                        windows.append(
                            window
                        )

                except json.JSONDecodeError:

                    print(
                        "[WARNING] Invalid JSON "
                        "record skipped."
                    )

    except Exception as error:

        print(
            f"[ERROR] Could not read input: "
            f"{error}"
        )

        return


    if not windows:

        print(
            "[WARNING] No behaviour windows found."
        )

        return


    # ========================================================
    # CREATE OUTPUT DIRECTORY
    # ========================================================

    os.makedirs(
        os.path.dirname(
            OUTPUT_FILE
        ),
        exist_ok=True
    )


    # ========================================================
    # WRITE OUTPUT
    # ========================================================

    processed = 0

    snapshot_windows = 0

    event_only_windows = 0

    total_successful_logins = 0

    total_failed_logins = 0


    try:

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as output:

            for window in windows:

                mapped = map_window(
                    window
                )

                output.write(
                    json.dumps(
                        mapped,
                        ensure_ascii=False
                    )
                    + "\n"
                )

                processed += 1

                total_successful_logins += (
                    mapped[
                        "successful_logins"
                    ]
                )

                total_failed_logins += (
                    mapped[
                        "failed_logins"
                    ]
                )

                if mapped[
                    "system_snapshot_available"
                ]:

                    snapshot_windows += 1

                else:

                    event_only_windows += 1

    except Exception as error:

        print(
            f"[ERROR] Could not write output: "
            f"{error}"
        )

        return


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        f"[INFO] Windows processed: "
        f"{processed}"
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
        f"[INFO] Successful logins preserved: "
        f"{total_successful_logins}"
    )

    print(
        f"[INFO] Failed logins preserved: "
        f"{total_failed_logins}"
    )

    print("------------------------------------------")

    print(
        "System feature mapping completed."
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print("==========================================")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    process()