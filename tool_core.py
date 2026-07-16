from collections import defaultdict
from datetime import datetime, timedelta, timezone

from manager import group_by_session
from parser import read_packets


IST = timezone(timedelta(hours=5, minutes=30))


def request_type_label(pkt):
    request_type = str(pkt.get("request_type")) if pkt.get("request_type") is not None else None

    mapping = {
        "1": "Initial",
        "2": "Update",
        "3": "Termination",
    }

    if request_type is None:
        return "Unknown"

    return mapping.get(request_type, request_type)


def load_sessions(path):
    return group_by_session(read_packets(path))


def build_indexes(sessions):
    session_ips = defaultdict(set)
    session_subscriptions = defaultdict(set)

    for session_id, packets in sessions.items():
        for pkt in packets:
            if pkt.get("ipv4"):
                session_ips[session_id].add(pkt["ipv4"])
            if pkt.get("ipv6"):
                session_ips[session_id].add(pkt["ipv6"])
            if pkt.get("subscription_id"):
                session_subscriptions[session_id].add(pkt["subscription_id"])

    return session_ips, session_subscriptions


def resolve_selected_sessions(
    sessions,
    session=None,
    subscription=None,
    ipv4=None,
    ipv6=None,
    result_code=None,
):
    session_ips, session_subscriptions = build_indexes(sessions)
    selected_sessions = set()

    if session:
        selected_sessions.add(session)
        target_ips = session_ips.get(session, set())

        for session_id, ips in session_ips.items():
            if ips & target_ips:
                selected_sessions.add(session_id)

    if subscription:
        target_sessions = {
            session_id
            for session_id, subscriptions in session_subscriptions.items()
            if subscription in subscriptions
        }
        selected_sessions.update(target_sessions)

    if ipv4 or ipv6:
        target_ip = ipv4 or ipv6
        target_sessions = {
            session_id
            for session_id, ips in session_ips.items()
            if target_ip in ips
        }
        selected_sessions.update(target_sessions)


    return selected_sessions


def iter_matching_packets(sessions, selected_sessions=None, result_code=None):

    if result_code:

        SUPPORTED_COMMANDS = {"258", "272", "274", "275"}

        requests = {}
        seen = set()
        count = 0

        for session_id, packets in sessions.items():

            if selected_sessions and session_id not in selected_sessions:
                continue

            for pkt in packets:

                command = str(pkt.get("command"))
                request_flag = str(pkt.get("request_flag"))

                if command in SUPPORTED_COMMANDS and request_flag == "1":

                    key = (
                        command,
                        str(pkt.get("hop_by_hop")),
                    )

                    requests[key] = pkt

            for pkt in packets:

                command = str(pkt.get("command"))
                request_flag = str(pkt.get("request_flag"))

                if (
                    command in SUPPORTED_COMMANDS
                    and request_flag == "0"
                    and str(pkt.get("result_code")) == str(result_code)
                ):

                    key = (
                        command,
                        str(pkt.get("hop_by_hop")),
                    )

                    req = requests.get(key)

                    if req:

                        unique = (
                            req["number"],
                            req["session"],
                        )

                        if unique not in seen:
                            seen.add(unique)
                            yield req

                            count += 1

                            if count >= 10:
                                return

        return
    
    for packets in sessions.values():
        for pkt in packets:

            if selected_sessions and pkt["session"] not in selected_sessions:
                continue

            yield pkt


def format_timestamp(timestamp):
    try:
        timestamp_value = float(timestamp)
    except (TypeError, ValueError):
        return str(timestamp)

    return datetime.fromtimestamp(timestamp_value, tz=timezone.utc).astimezone(IST).strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )


def format_packet(pkt):
    lines = [
        "=" * 80,
        f"Packet Number      : {pkt['number']}",
        f"Timestamp          : {format_timestamp(pkt['time'])}",
        f"Session ID         : {pkt['session']}",
        f"Subscription ID    : {pkt['subscription_id']}",
        f"Subscription Type  : {pkt['subscription_type']}",
        f"IPv4 Address       : {pkt['ipv4']}",
        f"IPv6 Address       : {pkt['ipv6']}",
        f"Request Type       : {request_type_label(pkt)}",
        f"Called Station Id  : {pkt['called_station_id']}",
        f"3GPP Charging Chars: {pkt['charging_characteristics']}",
        f"RAT Type           : {pkt['rat_type']}",
        f"Source             : {pkt['src']}",
        f"Destination        : {pkt['dst']}",
        f"Length             : {pkt['length']}",
        f"Command Code       : {pkt['command']}",
        f"Request Flag       : {pkt['request_flag']}",
        f"Application ID     : {pkt['application_id']}",
        f"Result Code        : {pkt['result_code']}",
        f"Origin Host        : {pkt['origin_host']}",
        f"Origin Realm       : {pkt['origin_realm']}",
        f"Destination Host   : {pkt['destination_host']}",
        f"Destination Realm  : {pkt['destination_realm']}",
        f"Hop-by-Hop ID      : {pkt['hop_by_hop']}",
        f"End-to-End ID      : {pkt['end_to_end']}",
        "-" * 80,
    ]

    return "\n".join(lines)


def build_output_text(sessions, selected_sessions, result_code=None):
    output_lines = ["Reading packets...", "", f"Found {len(sessions)} sessions", ""]
    found = False

    for pkt in iter_matching_packets(sessions, selected_sessions, result_code=result_code):
        found = True
        output_lines.append(format_packet(pkt))

    if not found:
        if selected_sessions:
            output_lines.append("No matching packets found.")
        else:
            output_lines.extend(["First 10 Sessions:", ""])
            output_lines.extend(list(sessions.keys())[:10])

    return "\n".join(output_lines)
