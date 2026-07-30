import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from manager import group_by_session
from parser import read_packets, read_session_index_rows
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

DEFAULT_RESULT_CODE_LIMIT = None

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


def is_request_packet(pkt):
    return is_request_flag_true(pkt.get("request_flag"))


def is_answer_packet(pkt):
    return is_request_flag_false(pkt.get("request_flag"))


def _new_index_entry():
    return {"ips": set(), "subscriptions": set(), "subscription_details": {}}


def _index_from_rows(rows):
    index = defaultdict(_new_index_entry)

    for row in rows:
        session_id = row.get("session")
        if session_id is None:
            continue
        entry = index[session_id]

        ipv4 = normalize_ip_value(row.get("ipv4"))
        if ipv4:
            entry["ips"].add(ipv4)

        ipv6 = normalize_ip_value(row.get("ipv6"))
        if ipv6:
            entry["ips"].add(ipv6)

        for sub in row.get("subscription_ids") or []:
            raw_sub = sub.get("value")
            normalized_sub = normalize_match_value(raw_sub)
            if not normalized_sub:
                continue
            entry["subscriptions"].add(normalized_sub)
            details = entry["subscription_details"].setdefault(
                normalized_sub, {"value": normalize_text(raw_sub), "type": None}
            )
            if details["type"] is None and sub.get("type") is not None:
                details["type"] = sub.get("type")

    return index


def _read_one_file_index(path):
    return path, _index_from_rows(read_session_index_rows(path))


def load_session_index(paths, progress_callback=None, max_workers=None):
    if isinstance(paths, str):
        paths = [paths]

    merged_index = defaultdict(_new_index_entry)
    total_files = len(paths)

    if total_files == 0:
        return merged_index

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_read_one_file_index, path): path for path in paths}

        for future in as_completed(futures):
            path = futures[future]
            _, file_index = future.result()

            for session_id, entry in file_index.items():
                merged_entry = merged_index[session_id]
                merged_entry["ips"] |= entry["ips"]
                merged_entry["subscriptions"] |= entry["subscriptions"]
                for normalized_sub, details in entry["subscription_details"].items():
                    existing = merged_entry["subscription_details"].setdefault(
                        normalized_sub, {"value": details["value"], "type": None}
                    )
                    if existing["type"] is None and details["type"] is not None:
                        existing["type"] = details["type"]

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    return merged_index


def resolve_selected_sessions(session_index, session=None, subscription=None, ipv4=None, ipv6=None):

    if not (session or subscription or ipv4 or ipv6):
        return None

    seed_sessions = set()

    if session:
        seed_sessions.add(str(session).strip())

    if subscription:
        subscription = normalize_match_value(subscription)
        seed_sessions.update(
            session_id
            for session_id, entry in session_index.items()
            if subscription in entry["subscriptions"]
        )

    if ipv4 or ipv6:
        target_ip = normalize_ip_value(ipv4 or ipv6)
        seed_sessions.update(
            session_id
            for session_id, entry in session_index.items()
            if target_ip in entry["ips"]
        )

    selected_sessions = set(seed_sessions)

    seed_ips = set()
    seed_subscriptions = set()
    for session_id in seed_sessions:
        entry = session_index.get(session_id)
        if entry:
            seed_ips |= entry["ips"]
            seed_subscriptions |= entry["subscriptions"]

    if seed_ips:
        selected_sessions.update(
            session_id
            for session_id, entry in session_index.items()
            if entry["ips"] & seed_ips
        )

    if seed_subscriptions:
        selected_sessions.update(
            session_id
            for session_id, entry in session_index.items()
            if entry["subscriptions"] & seed_subscriptions
        )

    return selected_sessions


def build_subscription_ids_output(session_index, filter_summary=None):
    output_lines = ["Reading packets...", "", f"Found {len(session_index)} sessions"]

    if filter_summary:
        output_lines.append(f"Filter: {filter_summary}")

    output_lines.append("")

    subscriptions = {}
    for session_id, entry in session_index.items():
        for normalized_sub, details in entry["subscription_details"].items():
            sub_entry = subscriptions.setdefault(
                normalized_sub,
                {"value": details["value"], "type": details["type"], "sessions": set()},
            )
            sub_entry["sessions"].add(session_id)
            if sub_entry["type"] is None and details["type"] is not None:
                sub_entry["type"] = details["type"]

    if not subscriptions:
        output_lines.append("No subscription IDs found.")
        return "\n".join(output_lines)

    output_lines.append(f"Found {len(subscriptions)} unique Subscription ID(s):")
    output_lines.append("")

    for normalized_id in sorted(subscriptions):
        entry = subscriptions[normalized_id]
        type_label = entry["type"] if entry["type"] is not None else "Unknown"
        output_lines.append(
            f"Subscription ID: {entry['value']:<30} Type: {type_label:<10} Sessions: {len(entry['sessions'])}"
        )

    return "\n".join(output_lines)


def _read_one_file_full(path, session_ids=None, source_file=None):
    return path, group_by_session(read_packets(path, session_ids=session_ids, source_file=source_file))


def load_full_sessions(paths, session_ids=None, progress_callback=None, max_workers=None, file_names=None):
    if isinstance(paths, str):
        paths = [paths]

    merged_sessions = defaultdict(list)
    total_files = len(paths)

    if total_files == 0:
        return merged_sessions

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _read_one_file_full, path, session_ids, (file_names or {}).get(path)
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            _, file_sessions = future.result()

            for session_id, packets in file_sessions.items():
                merged_sessions[session_id].extend(packets)

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    return merged_sessions


def _read_one_file_full_list(path, source_file=None):
    return path, list(read_packets(path, source_file=source_file))


def _stream_result_code_matches(
    paths,
    result_code,
    limit=None,
    command_filter=None,
    max_workers=None,
    progress_callback=None,
    file_names=None,
):
    result_code = normalize_text(result_code)
    command_filter = normalize_command_code(command_filter)

    if isinstance(paths, str):
        paths = [paths]

    pending_requests = {}
    matches = []
    seen = set()
    matched_count = 0
    limit_reached = False

    total_files = len(paths)
    if total_files == 0:
        return matches, {"matched_requests": 0, "limit_reached": False}

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    def process_file_packets(packets):
        nonlocal matched_count, limit_reached

        for pkt in packets:
            if limit is not None and matched_count >= limit:
                limit_reached = True
                return

            key = (pkt.get("session"), str(pkt.get("command")), str(pkt.get("hop_by_hop")))

            if is_request_packet(pkt):
                pending_requests[key] = pkt
                continue

            if not is_answer_packet(pkt):
                continue

            packet_code = pkt.get("experimental_result_code") or pkt.get("result_code")
            if not values_match(packet_code, result_code):
                continue

            request_pkt = pending_requests.pop(key, None)
            if request_pkt is None:
                continue

            if command_filter and normalize_command_code(request_pkt.get("command")) != command_filter:
                continue

            unique = (request_pkt.get("session"), request_pkt.get("number"))
            if unique in seen:
                continue

            seen.add(unique)
            matched_count += 1
            matches.append(request_pkt)

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_read_one_file_full_list, path, (file_names or {}).get(path)): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            _, packets = future.result()

            if not limit_reached:
                process_file_packets(packets)

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    matches.sort(key=lambda pkt: int(pkt["number"]))

    return matches, {"matched_requests": matched_count, "limit_reached": limit_reached}


def iter_result_code_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
    stats=None,
):

    result_code = normalize_text(result_code)
    if not result_code:
        return

    command_filter = normalize_command_code(command_filter)

    seen = set()
    matched_count = 0
    limit_reached = False
    matches = []

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

            packet_code = ( pkt.get("experimental_result_code") or pkt.get("result_code"))

            if not values_match(packet_code, result_code):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            request_index = requests_by_key.get(key)
            if request_index is None:

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
            matches.append(request_pkt)

        if limit is not None and matched_count >= limit:
            limit_reached = True
            break
    matches.sort(key=lambda pkt: int(pkt["number"]))

    for pkt in matches:
        yield pkt

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

    matched_packets = []

    for packets in sessions.values():
        for pkt in packets:
            if selected_sessions is not None and pkt["session"] not in selected_sessions:
                continue

            matched_packets.append(pkt)

    matched_packets.sort(key=lambda pkt: int(pkt["number"]))

    yield from matched_packets


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

    subscription_ids = pkt.get("subscription_ids") or []
    subscription_lines = []
    if subscription_ids:
        for sub in subscription_ids:
            type_label = sub.get("type") if sub.get("type") is not None else "Unknown"
            subscription_lines.append(f"Subscription ID    : {sub.get('value')} (Type: {type_label})")
    else:
        subscription_lines.append(f"Subscription ID    : {pkt.get('subscription_id')}")
        subscription_lines.append(f"Subscription Type  : {pkt.get('subscription_type')}")

    lines = [
        "=" * 80,
        f"File               : {pkt.get('file')}",
        f"Packet Number      : {pkt['number']}",
        f"Timestamp          : {format_timestamp(pkt['time'])}",
        f"Session ID         : {pkt['session']}",
        *subscription_lines,
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
    paths,
    session_index,
    selected_sessions,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    filter_summary=None,
    command_filter=None,
    progress_callback=None,
    max_workers=None,
    file_names=None,
):
    total_sessions = len(session_index)

    if selected_sessions is not None and not selected_sessions and not result_code:
        output_lines = ["Reading packets...", "", f"Found {total_sessions} sessions"]
        if filter_summary:
            output_lines.append(f"Filter: {filter_summary}")
        output_lines.append("")
        output_lines.append("No matching packets found.")
        return "\n".join(output_lines)

    if result_code:
        stats = {}

        if selected_sessions is not None:
            if not selected_sessions:
                matches = []
            else:
                sessions = load_full_sessions(
                    paths,
                    session_ids=selected_sessions,
                    progress_callback=progress_callback,
                    max_workers=max_workers,
                    file_names=file_names,
                )
                matches = list(
                    iter_result_code_packets(
                        sessions,
                        selected_sessions,
                        result_code=result_code,
                        limit=limit,
                        command_filter=command_filter,
                        stats=stats,
                    )
                )
        else:
            matches, stats = _stream_result_code_matches(
                paths,
                result_code,
                limit=limit,
                command_filter=command_filter,
                max_workers=max_workers,
                progress_callback=progress_callback,
                file_names=file_names,
            )

        output_lines = ["Reading packets...", "", f"Found {total_sessions} sessions"]
        if filter_summary:
            output_lines.append(f"Filter: {filter_summary}")
        output_lines.append("")

        if matches:
            for pkt in matches:
                output_lines.append(format_packet(pkt))
        else:
            output_lines.append("No matching packets found.")

        if stats.get("limit_reached"):
            output_lines.append(
                f"(Result stopped at limit={limit} matched requests. "
                "Increase or disable the limit to see more.)"
            )

        return "\n".join(output_lines)

    if selected_sessions is not None:
        sessions = load_full_sessions(
            paths,
            session_ids=selected_sessions,
            progress_callback=progress_callback,
            max_workers=max_workers,
            file_names=file_names,
        )

        output_lines = ["Reading packets...", "", f"Found {total_sessions} sessions"]
        if filter_summary:
            output_lines.append(f"Filter: {filter_summary}")
        output_lines.append("")

        found = False
        for pkt in iter_matching_packets(sessions):
            found = True
            output_lines.append(format_packet(pkt))

        if not found:
            output_lines.append("No matching packets found.")

        return "\n".join(output_lines)

    output_lines = ["Reading packets...", "", f"Found {total_sessions} sessions"]
    if filter_summary:
        output_lines.append(f"Filter: {filter_summary}")
    output_lines.append("")
    output_lines.extend(["First 10 Sessions:", ""])
    output_lines.extend(list(session_index.keys())[:10])

    return "\n".join(output_lines)