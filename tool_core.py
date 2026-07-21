from collections import defaultdict
from datetime import datetime, timedelta, timezone

from manager import group_by_session
from parser import read_packets
from diameter_utils import (
    command_family,
    is_request_flag_false,
    is_request_flag_true,
    normalize_command_code,
    normalize_ip_value,
    normalize_match_value,
    normalize_text,
    values_match,
)


IST = timezone(timedelta(hours=5, minutes=30))

DEFAULT_RESULT_CODE_LIMIT = 50

COMMAND_FILTER_CHOICES = [
    {"code": "272", "label": "Credit-Control-Request/Answer", "note": "Request received by PCRF"},
    {"code": "275", "label": "Session-Termination-Request/Answer", "note": "Request sent as well as received by PCRF"},
    {"code": "274", "label": "Abort-Session-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "258", "label": "Re-Auth-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "265", "label": "AA-Request/Answer", "note": "Authentication-Authorization exchange"},
    {"code": "8388635", "label": "Spending-Limit-Request/Answer", "note": "Sy interface (OCS spending limit)"},
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


def load_sessions(paths, progress_callback=None):
    """Read one or more pcap files and group all their packets by
    Diameter Session-Id into a single merged dict.
    """
    if isinstance(paths, str):
        paths = [paths]

    merged_sessions = defaultdict(list)

    for path in paths:
        def file_progress(count, _path=path):
            progress_callback(count, _path)

        file_sessions = group_by_session(
            read_packets(path, progress_callback=file_progress if progress_callback else None)
        )
        for session_id, packets in file_sessions.items():
            merged_sessions[session_id].extend(packets)

    return merged_sessions


def build_indexes(sessions):
    """Index each session's Framed-IP-Address(es) and Subscription-Id(s).

    IPs are normalized (case-folded, CIDR suffix stripped) so that a
    Framed-IPv6-Prefix on one interface still matches the bare
    Framed-IP-Address on another interface for the same subscriber -
    this is what lets an Rx (AA-Request) session link to its Gx/Sy
    session by shared IP.
    """
    session_ips = defaultdict(set)
    session_subscriptions = defaultdict(set)

    for session_id, packets in sessions.items():
        for pkt in packets:
            ipv4 = normalize_ip_value(pkt.get("ipv4"))
            if ipv4:
                session_ips[session_id].add(ipv4)

            ipv6 = normalize_ip_value(pkt.get("ipv6"))
            if ipv6:
                session_ips[session_id].add(ipv6)

            if pkt.get("subscription_id"):
                normalized_subscription = normalize_match_value(pkt["subscription_id"])
                if normalized_subscription:
                    session_subscriptions[session_id].add(normalized_subscription)

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
    # (empty set).
    if not (session or subscription or ipv4 or ipv6):
        return None

    session_ips, session_subscriptions = build_indexes(sessions)

    seed_sessions = set()

    if session:
        seed_sessions.add(str(session).strip())

    if subscription:
        subscription = normalize_match_value(subscription)
        seed_sessions.update(
            session_id
            for session_id, subscriptions in session_subscriptions.items()
            if subscription in subscriptions
        )

    if ipv4 or ipv6:
        target_ip = normalize_ip_value(ipv4 or ipv6)
        seed_sessions.update(
            session_id
            for session_id, ips in session_ips.items()
            if target_ip in ips
        )

    # Cross-link (one hop): pulls in any session sharing an IP or a
    # Subscription-Id with a seed session. This is what surfaces Rx
    # (AA-Request) sessions - which carry only a Framed-IP-Address, no
    # Subscription-Id - and Sy (Spending-Limit) sessions - which carry
    # only a Subscription-Id, no Framed-IP-Address - regardless of
    # which attribute (session/subscription/IP) was originally searched.
    selected_sessions = set(seed_sessions)

    seed_ips = set()
    seed_subscriptions = set()
    for session_id in seed_sessions:
        seed_ips |= session_ips.get(session_id, set())
        seed_subscriptions |= session_subscriptions.get(session_id, set())

    if seed_ips:
        selected_sessions.update(
            session_id
            for session_id, ips in session_ips.items()
            if ips & seed_ips
        )

    if seed_subscriptions:
        selected_sessions.update(
            session_id
            for session_id, subscriptions in session_subscriptions.items()
            if subscriptions & seed_subscriptions
        )

    return selected_sessions


def is_request_packet(pkt):
    return is_request_flag_true(pkt.get("request_flag"))


def is_answer_packet(pkt):
    return is_request_flag_false(pkt.get("request_flag"))


def iter_result_code_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
    stats=None,
):
    """Yield the Request that corresponds to every Answer matching
    `result_code` (and `command_filter`, if given).

    Only the Request is yielded - never the matching Answer, and never
    any other packet from that Answer's session. Each Request is yielded
    at most once even if it were somehow reachable via more than one
    matching Answer.

    `limit` caps the total number of Requests yielded (mixed request
    types when `command_filter` is not set, or that command family's
    requests when it is).
    """

    result_code = normalize_text(result_code)
    if not result_code:
        return

    command_filter = normalize_command_code(command_filter)

    seen = set()
    matched_count = 0
    limit_reached = False

    for session_id, packets in sessions.items():
        if limit is not None and matched_count >= limit:
            limit_reached = True
            break

        if selected_sessions is not None and session_id not in selected_sessions:
            continue

        requests_by_key = {}
        for index, pkt in enumerate(packets):
            if not is_request_packet(pkt):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            requests_by_key[key] = index

        for pkt in packets:
            if not is_answer_packet(pkt):
                continue

            if not values_match(pkt.get("result_code"), result_code):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            request_index = requests_by_key.get(key)
            if request_index is None:
                # No corresponding Request was captured - nothing to
                # output for this Answer.
                continue

            request_pkt = packets[request_index]

            if command_filter and normalize_command_code(request_pkt.get("command")) != command_filter:
                continue

            unique = (request_pkt.get("session"), request_pkt.get("number"))
            if unique in seen:
                continue

            if limit is not None and matched_count >= limit:
                limit_reached = True
                break

            seen.add(unique)
            matched_count += 1
            yield request_pkt

        if limit is not None and matched_count >= limit:
            limit_reached = True
            break

    if stats is not None:
        stats["matched_requests"] = matched_count
        stats["limit_reached"] = limit_reached


def iter_matching_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
    stats=None,
):
    if result_code:
        yield from iter_result_code_packets(
            sessions,
            selected_sessions,
            result_code=result_code,
            limit=limit,
            command_filter=command_filter,
            stats=stats,
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
    stats = {}

    for pkt in iter_matching_packets(
        sessions,
        selected_sessions,
        result_code=result_code,
        limit=limit,
        command_filter=command_filter,
        stats=stats,
    ):
        found = True
        match_count += 1
        output_lines.append(format_packet(pkt))

    if result_code and stats.get("limit_reached"):
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