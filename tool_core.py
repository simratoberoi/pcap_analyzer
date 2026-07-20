from collections import defaultdict
from datetime import datetime, timedelta, timezone
from bisect import bisect_left

from manager import group_by_session
from parser import read_packets
from diameter_utils import (
    command_family,
    is_request_flag_false,
    is_request_flag_true,
    is_supported_result_command,
    normalize_command_code,
    normalize_text,
    values_match,
)


IST = timezone(timedelta(hours=5, minutes=30))

DEFAULT_RESULT_CODE_LIMIT = 50

# The four command families selectable as a sub-filter on a Result Code
# search. "code" must match a key in diameter_utils.COMMAND_METADATA.
COMMAND_FILTER_CHOICES = [
    {"code": "272", "label": "Credit-Control-Request/Answer", "note": "Request received by PCRF"},
    {"code": "275", "label": "Session-Termination-Request/Answer", "note": "Request sent as well as received by PCRF"},
    {"code": "274", "label": "Abort-Session-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "258", "label": "Re-Auth-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "265", "label": "AA-Request/Answer", "note": "Authentication-Authorization exchange"},
]


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
                session_ips[session_id].add(str(pkt["ipv4"]).strip())
            if pkt.get("ipv6"):
                session_ips[session_id].add(str(pkt["ipv6"]).strip())
            if pkt.get("subscription_id"):
                session_subscriptions[session_id].add(str(pkt["subscription_id"]).strip())

    return session_ips, session_subscriptions


def resolve_selected_sessions(
    sessions,
    session=None,
    subscription=None,
    ipv4=None,
    ipv6=None,
):
    # No filter values supplied at all -> no session restriction (None),
    # distinct from a filter that was supplied but matched zero sessions
    # (empty set). Downstream code relies on this distinction: conflating
    # the two used to make an unmatched filter (e.g. an IPv4 address not
    # present in the capture) silently fall back to showing every packet
    # in the capture instead of "no matches", which is what was blowing up
    # the UI on large captures.
    if not (session or subscription or ipv4 or ipv6):
        return None

    session_ips, session_subscriptions = build_indexes(sessions)
    selected_sessions = set()

    if session:
        session = str(session).strip()
        selected_sessions.add(session)
        target_ips = session_ips.get(session, set())

        for session_id, ips in session_ips.items():
            if ips & target_ips:
                selected_sessions.add(session_id)

    if subscription:
        subscription = str(subscription).strip()
        target_sessions = {
            session_id
            for session_id, subscriptions in session_subscriptions.items()
            if subscription in subscriptions
        }
        selected_sessions.update(target_sessions)

    if ipv4 or ipv6:
        target_ip = str(ipv4 or ipv6).strip()
        target_sessions = {
            session_id
            for session_id, ips in session_ips.items()
            if target_ip in ips
        }
        selected_sessions.update(target_sessions)

    return selected_sessions


def is_supported_request(pkt):
    return is_supported_result_command(pkt.get("command")) and is_request_flag_true(pkt.get("request_flag"))


def is_supported_answer(pkt):
    return is_supported_result_command(pkt.get("command")) and is_request_flag_false(pkt.get("request_flag"))


def request_neighbors(request_positions, answer_index):
    insertion_point = bisect_left(request_positions, answer_index)
    previous_request_index = request_positions[insertion_point - 1] if insertion_point > 0 else None
    next_request_index = request_positions[insertion_point] if insertion_point < len(request_positions) else None

    return previous_request_index, next_request_index


def is_failed_result_code(result_code):
    result_code = normalize_text(result_code)
    return bool(result_code) and not result_code.startswith("2")


def iter_result_code_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
):

    result_code = normalize_text(result_code)
    if not result_code:
        return

    command_filter = normalize_command_code(command_filter)

    seen = set()
    matched_requests = set()
    limit_reached = False

    for session_id, packets in sessions.items():
        if selected_sessions is not None and session_id not in selected_sessions:
            continue

        requests_by_key = {}
        request_positions = []

        for index, pkt in enumerate(packets):
            if not is_supported_request(pkt):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            requests_by_key[key] = index
            request_positions.append(index)

        selected_indexes = set()

        for index, pkt in enumerate(packets):
            if not is_supported_answer(pkt):
                continue

            if not values_match(pkt.get("result_code"), result_code):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            request_index = requests_by_key.get(key)

            if command_filter:
                # The command-family sub-filter only gates whether this failed
                # answer's entry is included at all, based on the command of
                # its own corresponding request. If there's no corresponding
                # request to check, or its command doesn't match, skip this
                # answer entirely (its before/after context is skipped too).
                if request_index is None:
                    continue
                if normalize_command_code(packets[request_index].get("command")) != command_filter:
                    continue

            if request_index is not None:
                request_unique = (session_id, packets[request_index].get("number"))
                if request_unique not in matched_requests:
                    if limit is not None and len(matched_requests) >= limit:
                        limit_reached = True
                        break

                    matched_requests.add(request_unique)

                selected_indexes.add(request_index)

            if is_failed_result_code(pkt.get("result_code")):
                previous_request_index, next_request_index = request_neighbors(request_positions, index)
                if previous_request_index is not None:
                    selected_indexes.add(previous_request_index)
                if next_request_index is not None:
                    selected_indexes.add(next_request_index)

        for index in sorted(selected_indexes):
            pkt = packets[index]
            unique = (pkt.get("session"), pkt.get("number"))
            if unique in seen:
                continue

            seen.add(unique)
            yield pkt

        if limit_reached or (limit is not None and len(matched_requests) >= limit):
            break


def iter_matching_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
):
    if result_code:
        yield from iter_result_code_packets(
            sessions,
            selected_sessions,
            result_code=result_code,
            limit=limit,
            command_filter=command_filter,
        )
        return

    for packets in sessions.values():
        for pkt in packets:
            if selected_sessions is not None and pkt["session"] not in selected_sessions:
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
    bandwidth = pkt.get("bandwidth") or {}
    flags = pkt.get("flags") or {}

    flag_lines = []
    if "Request" in flags:
        flag_lines.append(f"Request Flag       : {flags['Request']}")

    for flag_label, flag_value in flags.items():
        if flag_label == "Request":
            continue
        flag_lines.append(f"{flag_label:<18} : {flag_value}")

    bandwidth_lines = []
    for field_label, field_value in bandwidth.items():
        if field_value is None:
            continue
        bandwidth_lines.append(f"{field_label:<18} : {field_value}")

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
        f"Command Name       : {command_family(pkt.get('command'))}",
        f"Message Type       : {pkt.get('message_type') or command_family(pkt.get('command'))}",
    ]

    if bandwidth_lines:
        lines.append("Bandwidth:")
        lines.extend(bandwidth_lines)

    lines.extend(
        [
        f"Source             : {pkt['src']}",
        f"Destination        : {pkt['dst']}",
        f"Length             : {pkt['length']}",
        f"Command Code       : {pkt['command']}",
    ]
    )

    lines.extend(flag_lines)

    lines.extend(
        [
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
    )

    return "\n".join(lines)


def build_output_text(
    sessions,
    selected_sessions,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    filter_summary=None,
    command_filter=None,
):
    output_lines = ["Reading packets...", "", f"Found {len(sessions)} sessions"]

    if filter_summary:
        output_lines.append(f"Filter: {filter_summary}")

    output_lines.append("")

    found = False
    match_count = 0

    for pkt in iter_matching_packets(
        sessions,
        selected_sessions,
        result_code=result_code,
        limit=limit,
        command_filter=command_filter,
    ):
        found = True
        match_count += 1
        output_lines.append(format_packet(pkt))

    if result_code and limit is not None and match_count >= limit:
        output_lines.append(
            f"(Result stopped at limit={limit} matched requests. "
            "Increase or disable the limit to see more.)"
        )

    if not found:
        if result_code:
            output_lines.append("No matching packets found.")
        elif selected_sessions is not None:
            output_lines.append("No matching packets found.")
        else:
            output_lines.extend(["First 10 Sessions:", ""])
            output_lines.extend(list(sessions.keys())[:10])

    return "\n".join(output_lines)