import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = (
    PROJECT_ROOT
    / "Collectors"
    / "event_logs.jsonl"
)

POLL_INTERVAL = 5

# Number of recent events requested on each poll.
# A larger number reduces the chance of missing events
# during periods of high activity.
MAX_EVENTS = 50


# Windows logs to monitor
EVENT_LOGS = [
    "Security",
    "System"
]


# ============================================================
# IMPORTANT EVENT IDS
# ============================================================

IMPORTANT_EVENT_IDS = {

    # Authentication
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4647: "User Initiated Logoff",

    # Privileges
    4672: "Special Privileges Assigned",

    # Process activity
    4688: "Process Created",

    # Account management
    4720: "User Account Created",
    4726: "User Account Deleted",
    4732: "User Added To Local Group",

    # Services
    7045: "New Service Installed",
}


# ============================================================
# XML NAMESPACE
# ============================================================

EVENT_NAMESPACE = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


# ============================================================
# RUN WEVTUTIL
# ============================================================

def get_event_xml(log_name):

    command = [

        "wevtutil",

        "qe",

        log_name,

        f"/c:{MAX_EVENTS}",

        "/rd:true",

        "/f:xml"

    ]


    try:

        result = subprocess.run(

            command,

            capture_output=True,

            text=True,

            encoding="utf-8",

            errors="replace",

            timeout=20

        )


        if result.returncode != 0:

            print(
                f"[ERROR] Could not read "
                f"{log_name} log."
            )

            print(
                result.stderr.strip()
            )

            return []


        if not result.stdout.strip():

            return []


        return parse_xml_events(
            result.stdout
        )


    except subprocess.TimeoutExpired:

        print(
            f"[WARNING] Timeout while reading "
            f"{log_name} log."
        )

        return []


    except Exception as error:

        print(
            f"[ERROR] Failed reading "
            f"{log_name} log:"
        )

        print(error)

        return []


# ============================================================
# PARSE XML EVENTS
# ============================================================

def parse_xml_events(xml_text):

    events = []


    # wevtutil returns multiple XML Event elements.
    # Wrap them in a temporary root so ElementTree
    # can parse them together.

    wrapped_xml = (

        "<Events>"

        +
        xml_text

        +
        "</Events>"

    )


    try:

        root = ET.fromstring(
            wrapped_xml
        )


    except ET.ParseError as error:

        print(
            "[WARNING] Could not parse "
            "Windows event XML."
        )

        print(error)

        return []


    for event_element in root:

        try:

            events.append(
                parse_single_event(
                    event_element
                )
            )

        except Exception as error:

            print(
                "[WARNING] Could not parse "
                f"one event: {error}"
            )


    return events


# ============================================================
# PARSE SINGLE EVENT
# ============================================================

def parse_single_event(
    event_element
):

    system = event_element.find(
        "e:System",
        EVENT_NAMESPACE
    )


    if system is None:

        return {}


    # --------------------------------------------------------
    # Basic System information
    # --------------------------------------------------------

    provider_element = system.find(
        "e:Provider",
        EVENT_NAMESPACE
    )


    provider_name = None

    provider_guid = None


    if provider_element is not None:

        provider_name = (
            provider_element.get("Name")
        )

        provider_guid = (
            provider_element.get("Guid")
        )


    event_id_element = system.find(
        "e:EventID",
        EVENT_NAMESPACE
    )


    event_id = 0


    if event_id_element is not None:

        try:

            event_id = int(
                event_id_element.text
            )

        except (TypeError, ValueError):

            event_id = 0


    level_element = system.find(
        "e:Level",
        EVENT_NAMESPACE
    )


    task_element = system.find(
        "e:Task",
        EVENT_NAMESPACE
    )


    opcode_element = system.find(
        "e:Opcode",
        EVENT_NAMESPACE
    )


    computer_element = system.find(
        "e:Computer",
        EVENT_NAMESPACE
    )


    channel_element = system.find(
        "e:Channel",
        EVENT_NAMESPACE
    )


    record_id_element = system.find(
        "e:EventRecordID",
        EVENT_NAMESPACE
    )


    security_element = system.find(
        "e:Security",
        EVENT_NAMESPACE
    )


    # --------------------------------------------------------
    # EventData
    # --------------------------------------------------------

    event_data = {}

    data_element = event_element.find(
        "e:EventData",
        EVENT_NAMESPACE
    )


    if data_element is not None:

        for data in data_element:

            name = data.get("Name")

            value = data.text


            if name:

                event_data[name] = value


    # --------------------------------------------------------
    # User information
    # --------------------------------------------------------

    username = first_available(

        event_data,

        [
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "UserName"
        ]

    )


    domain = first_available(

        event_data,

        [
            "TargetDomainName",
            "SubjectDomainName",
            "AccountDomain"
        ]

    )


    # --------------------------------------------------------
    # Authentication information
    # --------------------------------------------------------

    logon_type = to_int_or_none(

        event_data.get(
            "LogonType"
        )

    )


    authentication_package = (

        event_data.get(
            "AuthenticationPackageName"
        )

    )


    logon_process = (

        event_data.get(
            "LogonProcessName"
        )

    )


    # --------------------------------------------------------
    # Network information
    # --------------------------------------------------------

    source_ip = first_available(

        event_data,

        [
            "IpAddress",
            "SourceAddress",
            "SourceNetworkAddress"
        ]

    )


    source_port = to_int_or_none(

        first_available(

            event_data,

            [
                "IpPort",
                "SourcePort"
            ]

        )

    )


    workstation = first_available(

        event_data,

        [
            "WorkstationName",
            "Workstation"
        ]

    )


    # --------------------------------------------------------
    # Process information
    # --------------------------------------------------------

    process_id = first_available(

        event_data,

        [
            "NewProcessId",
            "ProcessId"
        ]

    )


    process_name = first_available(

        event_data,

        [
            "NewProcessName",
            "ProcessName"
        ]

    )


    parent_process = first_available(

        event_data,

        [
            "ParentProcessName"
        ]

    )


    command_line = first_available(

        event_data,

        [
            "CommandLine"
        ]

    )


    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    time_created_element = system.find(
        "e:TimeCreated",
        EVENT_NAMESPACE
    )


    timestamp = None


    if time_created_element is not None:

        timestamp = (
            time_created_element.get(
                "SystemTime"
            )
        )


    if timestamp is None:

        timestamp = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # --------------------------------------------------------
    # Event record ID
    # --------------------------------------------------------

    record_id = None


    if record_id_element is not None:

        record_id = to_int_or_none(

            record_id_element.text

        )


    # --------------------------------------------------------
    # Build structured record
    # --------------------------------------------------------

    record = {

        "timestamp": timestamp,

        "log_name": channel_element.text
        if channel_element is not None
        else None,

        "event_id": event_id,

        "event_name":
            IMPORTANT_EVENT_IDS.get(
                event_id,
                "Other Event"
            ),

        "provider": provider_name,

        "provider_guid": provider_guid,

        "level":
            level_element.text
            if level_element is not None
            else None,

        "task":
            task_element.text
            if task_element is not None
            else None,

        "opcode":
            opcode_element.text
            if opcode_element is not None
            else None,

        "computer":
            computer_element.text
            if computer_element is not None
            else None,

        "record_id": record_id,

        # Authentication
        "username": username,

        "domain": domain,

        "logon_type": logon_type,

        "authentication_package":
            authentication_package,

        "logon_process":
            logon_process,

        # Network
        "source_ip": source_ip,

        "source_port": source_port,

        "workstation": workstation,

        # Process
        "process_id": process_id,

        "process_name": process_name,

        "parent_process":
            parent_process,

        "command_line":
            command_line,

        # Complete structured event data
        "event_data": event_data,

        "collected_at":
            datetime.now(
                timezone.utc
            ).isoformat()

    }


    return record


# ============================================================
# HELPER: FIRST AVAILABLE VALUE
# ============================================================

def first_available(
    dictionary,
    keys
):

    for key in keys:

        value = dictionary.get(
            key
        )


        if value not in (
            None,
            "",
            "-"
        ):

            return value


    return None


# ============================================================
# HELPER: INTEGER
# ============================================================

def to_int_or_none(value):

    if value is None:

        return None


    try:

        return int(
            str(value),
            0
        )

    except (TypeError, ValueError):

        try:

            return int(value)

        except (TypeError, ValueError):

            return None


# ============================================================
# EVENT UNIQUE KEY
# ============================================================

def get_event_key(
    event
):

    return (

        event.get(
            "log_name"
        ),

        event.get(
            "record_id"
        ),

        event.get(
            "event_id"
        ),

        event.get(
            "timestamp"
        )

    )


# ============================================================
# SAVE EVENT
# ============================================================

def save_event(
    event
):

    try:

        with open(

            OUTPUT_FILE,

            "a",

            encoding="utf-8"

        ) as file:

            file.write(

                json.dumps(

                    event,

                    ensure_ascii=False

                )

                +

                "\n"

            )


    except Exception as error:

        print(
            "[ERROR] Could not save event:"
        )

        print(error)


# ============================================================
# DISPLAY EVENT
# ============================================================

def display_event(
    event
):

    event_id = event.get(
        "event_id"
    )


    print("\n[IMPORTANT EVENT]")

    print(
        f"Time     : "
        f"{event.get('timestamp')}"
    )

    print(
        f"Log      : "
        f"{event.get('log_name')}"
    )

    print(
        f"Event ID : "
        f"{event_id}"
    )

    print(
        f"Type     : "
        f"{event.get('event_name')}"
    )

    print(
        f"User     : "
        f"{event.get('username')}"
    )

    print(
        f"Source IP: "
        f"{event.get('source_ip')}"
    )

    print(
        f"Process  : "
        f"{event.get('process_name')}"
    )

    print("------------------------------------------")


# ============================================================
# INITIALIZATION
# ============================================================

def initialize():

    print(
        "=========================================="
    )

    print(
        "      WINDOWS EVENT LOG MONITOR"
    )

    print(
        "=========================================="
    )

    print(
        f"Output file  : {OUTPUT_FILE}"
    )

    print(
        f"Poll interval: {POLL_INTERVAL} seconds"
    )

    print(
        f"Logs         : "
        f"{', '.join(EVENT_LOGS)}"
    )

    print("------------------------------------------")


    OUTPUT_FILE.parent.mkdir(

        parents=True,

        exist_ok=True

    )


# ============================================================
# MAIN MONITOR
# ============================================================

def run():

    initialize()


    # --------------------------------------------------------
    # Events already seen
    # --------------------------------------------------------

    processed_events = set()


    # --------------------------------------------------------
    # Establish baseline
    # --------------------------------------------------------

    print(
        "\n[INFO] Reading initial Windows events..."
    )


    initial_count = 0


    for log_name in EVENT_LOGS:

        events = get_event_xml(
            log_name
        )


        for event in events:

            if not event:

                continue


            key = get_event_key(
                event
            )


            processed_events.add(
                key
            )


            initial_count += 1


    print(
        f"[INFO] Initial events loaded: "
        f"{initial_count}"
    )


    print(
        "[INFO] Monitoring for new events..."
    )

    print("------------------------------------------")


    # --------------------------------------------------------
    # Continuous monitoring
    # --------------------------------------------------------

    while True:

        new_events = 0


        for log_name in EVENT_LOGS:

            events = get_event_xml(
                log_name
            )


            for event in events:

                if not event:

                    continue


                key = get_event_key(
                    event
                )


                if key in processed_events:

                    continue


                # --------------------------------------------
                # Remember event
                # --------------------------------------------

                processed_events.add(
                    key
                )


                # --------------------------------------------
                # Save
                # --------------------------------------------

                save_event(
                    event
                )


                new_events += 1


                # --------------------------------------------
                # Display important events
                # --------------------------------------------

                event_id = event.get(
                    "event_id"
                )


                if event_id in IMPORTANT_EVENT_IDS:

                    display_event(
                        event
                    )


        if new_events > 0:

            print(
                f"[INFO] Captured "
                f"{new_events} new event(s)."
            )


        time.sleep(
            POLL_INTERVAL
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
            "Stopping Windows Event Log monitor..."
        )

        print(
            "Windows Event Log monitor stopped."
        )