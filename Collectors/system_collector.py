import json
import time
import socket
from pathlib import Path
from datetime import datetime, timezone

import psutil


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = (
    PROJECT_ROOT
    / "Collectors"
    / "system_events.jsonl"
)

COLLECTION_INTERVAL = 5


# ============================================================
# SAFE HELPERS
# ============================================================

def safe_value(function, default=None):

    try:
        return function()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError
    ):

        return default

    except Exception:

        return default


def get_process_name(process):

    return safe_value(
        process.name,
        "Unknown"
    )


def get_process_username(process):

    return safe_value(
        process.username,
        None
    )


def get_process_create_time(process):

    return safe_value(
        process.create_time,
        None
    )


def get_process_cpu(process):

    return safe_value(
        process.cpu_percent(interval=None),
        0.0
    )


def get_process_memory(process):

    memory = safe_value(
        process.memory_percent,
        0.0
    )

    return memory if memory is not None else 0.0


# ============================================================
# CPU INFORMATION
# ============================================================

def collect_cpu():

    cpu_percent = psutil.cpu_percent(
        interval=1
    )

    cpu_count = psutil.cpu_count(
        logical=True
    )

    physical_cpu_count = psutil.cpu_count(
        logical=False
    )

    return {

        "cpu_percent": cpu_percent,

        "logical_cpu_count":
            cpu_count,

        "physical_cpu_count":
            physical_cpu_count

    }


# ============================================================
# MEMORY INFORMATION
# ============================================================

def collect_memory():

    memory = psutil.virtual_memory()

    swap = psutil.swap_memory()

    return {

        "memory_percent":
            memory.percent,

        "memory_total_bytes":
            memory.total,

        "memory_available_bytes":
            memory.available,

        "memory_used_bytes":
            memory.used,

        "swap_percent":
            swap.percent,

        "swap_used_bytes":
            swap.used

    }


# ============================================================
# DISK INFORMATION
# ============================================================

def collect_disk():

    try:

        disk = psutil.disk_usage(
            "C:\\"
        )

        return {

            "disk_percent":
                disk.percent,

            "disk_total_bytes":
                disk.total,

            "disk_used_bytes":
                disk.used,

            "disk_free_bytes":
                disk.free

        }

    except Exception:

        return {

            "disk_percent": 0.0,

            "disk_total_bytes": 0,

            "disk_used_bytes": 0,

            "disk_free_bytes": 0

        }


# ============================================================
# PROCESS INFORMATION
# ============================================================

def collect_processes():

    processes = []

    total_processes = 0

    process_cpu_total = 0.0

    process_memory_total = 0.0

    high_cpu_processes = 0

    high_memory_processes = 0


    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "username",
            "create_time"
        ]
    ):

        try:

            total_processes += 1


            cpu = get_process_cpu(
                process
            )

            memory = get_process_memory(
                process
            )


            process_cpu_total += cpu

            process_memory_total += memory


            if cpu >= 50:

                high_cpu_processes += 1


            if memory >= 5:

                high_memory_processes += 1


            process_record = {

                "pid":
                    process.info.get(
                        "pid"
                    ),

                "name":
                    process.info.get(
                        "name"
                    ),

                "username":
                    process.info.get(
                        "username"
                    ),

                "create_time":
                    process.info.get(
                        "create_time"
                    ),

                "cpu_percent":
                    cpu,

                "memory_percent":
                    memory

            }


            processes.append(
                process_record
            )


        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            continue


    return {

        "process_count":
            total_processes,

        "process_cpu_total":
            round(
                process_cpu_total,
                2
            ),

        "process_memory_total":
            round(
                process_memory_total,
                2
            ),

        "high_cpu_process_count":
            high_cpu_processes,

        "high_memory_process_count":
            high_memory_processes,

        "processes":
            processes

    }


# ============================================================
# NETWORK CONNECTION INFORMATION
# ============================================================

def collect_connections():

    connections = []

    established = 0

    listening = 0

    close_wait = 0

    time_wait = 0

    tcp_count = 0

    udp_count = 0


    try:

        raw_connections = (
            psutil.net_connections(
                kind="inet"
            )
        )


    except Exception:

        raw_connections = []


    for connection in raw_connections:

        try:

            status = (
                connection.status
            )


            if connection.type == socket.SOCK_STREAM:

                tcp_count += 1

            elif connection.type == socket.SOCK_DGRAM:

                udp_count += 1


            if status == "ESTABLISHED":

                established += 1

            elif status == "LISTEN":

                listening += 1

            elif status == "CLOSE_WAIT":

                close_wait += 1

            elif status == "TIME_WAIT":

                time_wait += 1


            local_address = None
            remote_address = None


            if connection.laddr:

                local_address = {

                    "ip":
                        connection.laddr.ip,

                    "port":
                        connection.laddr.port

                }


            if connection.raddr:

                remote_address = {

                    "ip":
                        connection.raddr.ip,

                    "port":
                        connection.raddr.port

                }


            connections.append({

                "family":
                    str(connection.family),

                "type":
                    str(connection.type),

                "status":
                    status,

                "pid":
                    connection.pid,

                "local":
                    local_address,

                "remote":
                    remote_address

            })


        except Exception:

            continue


    return {

        "network_connection_count":
            len(connections),

        "tcp_connection_count":
            tcp_count,

        "udp_connection_count":
            udp_count,

        "established_connection_count":
            established,

        "listening_connection_count":
            listening,

        "close_wait_count":
            close_wait,

        "time_wait_count":
            time_wait,

        "connections":
            connections

    }


# ============================================================
# USER INFORMATION
# ============================================================

def collect_users():

    users = []


    try:

        for user in psutil.users():

            users.append({

                "username":
                    user.name,

                "terminal":
                    user.terminal,

                "host":
                    user.host,

                "started":
                    user.started

            })

    except Exception:

        pass


    return {

        "active_user_count":
            len(users),

        "active_users":
            users

    }


# ============================================================
# SYSTEM UPTIME
# ============================================================

def collect_system_time():

    boot_timestamp = (
        psutil.boot_time()
    )

    current_timestamp = (
        time.time()
    )

    uptime = (
        current_timestamp
        -
        boot_timestamp
    )


    return {

        "boot_time":
            datetime.fromtimestamp(
                boot_timestamp,
                timezone.utc
            ).isoformat(),

        "uptime_seconds":
            round(
                uptime,
                2
            )

    }


# ============================================================
# COMPLETE SYSTEM SNAPSHOT
# ============================================================

def collect_snapshot():

    snapshot = {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "hostname":
            socket.gethostname()

    }


    snapshot.update(
        collect_cpu()
    )

    snapshot.update(
        collect_memory()
    )

    snapshot.update(
        collect_disk()
    )

    snapshot.update(
        collect_processes()
    )

    snapshot.update(
        collect_connections()
    )

    snapshot.update(
        collect_users()
    )

    snapshot.update(
        collect_system_time()
    )


    return snapshot


# ============================================================
# SAVE SNAPSHOT
# ============================================================

def save_snapshot(
    snapshot
):

    try:

        with open(

            OUTPUT_FILE,

            "a",

            encoding="utf-8"

        ) as file:

            file.write(

                json.dumps(
                    snapshot,
                    ensure_ascii=False
                )

                +

                "\n"

            )

    except Exception as error:

        print(
            "[ERROR] Could not save "
            "system snapshot:"
        )

        print(error)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

def display_summary(
    snapshot
):

    print(
        "\n[SYSTEM SNAPSHOT]"
    )

    print(
        f"CPU Usage       : "
        f"{snapshot['cpu_percent']:.1f}%"
    )

    print(
        f"Memory Usage    : "
        f"{snapshot['memory_percent']:.1f}%"
    )

    print(
        f"Disk Usage      : "
        f"{snapshot['disk_percent']:.1f}%"
    )

    print(
        f"Processes       : "
        f"{snapshot['process_count']}"
    )

    print(
        f"High CPU        : "
        f"{snapshot['high_cpu_process_count']}"
    )

    print(
        f"Network Conn.   : "
        f"{snapshot['network_connection_count']}"
    )

    print(
        f"Established     : "
        f"{snapshot['established_connection_count']}"
    )

    print(
        f"Listening       : "
        f"{snapshot['listening_connection_count']}"
    )

    print(
        f"Active Users    : "
        f"{snapshot['active_user_count']}"
    )

    print(
        "------------------------------------------"
    )


# ============================================================
# MAIN
# ============================================================

def run():

    print(
        "=========================================="
    )

    print(
        "       WINDOWS SYSTEM MONITOR"
    )

    print(
        "=========================================="
    )

    print(
        f"Output file : {OUTPUT_FILE}"
    )

    print(
        f"Interval    : "
        f"{COLLECTION_INTERVAL} seconds"
    )

    print("------------------------------------------")


    OUTPUT_FILE.parent.mkdir(

        parents=True,

        exist_ok=True

    )


    while True:

        try:

            snapshot = (
                collect_snapshot()
            )


            save_snapshot(
                snapshot
            )


            display_summary(
                snapshot
            )


            time.sleep(
                COLLECTION_INTERVAL
            )


        except KeyboardInterrupt:

            raise


        except Exception as error:

            print(
                "[ERROR] System collection "
                "failed:"
            )

            print(error)

            time.sleep(
                COLLECTION_INTERVAL
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        run()

    except KeyboardInterrupt:

        print("\n")

        print(
            "Stopping Windows System Monitor..."
        )

        print(
            "Windows System Monitor stopped."
        )