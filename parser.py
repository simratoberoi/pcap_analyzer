import csv
import os
import platform
import shutil
import subprocess

from diameter_utils import (
    command_family,
    extract_bandwidth_fields,
    extract_diameter_flags,
    message_type,
)


def resolve_tshark_path():
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which("tshark") or shutil.which("tshark.exe")
    if which_path:
        return which_path

    system = platform.system()
    if system == "Darwin":
        candidates = [
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            "/opt/homebrew/bin/tshark",
            "/usr/local/bin/tshark",
        ]
    elif system == "Windows":
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
    else:
        candidates = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/snap/bin/tshark",
        ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "Could not find the tshark binary on this machine. Install "
        "Wireshark/tshark, or set the TSHARK_PATH environment variable "
        "to its full path, e.g.:\n"
        "  export TSHARK_PATH=/path/to/tshark        # macOS/Linux\n"
        "  set TSHARK_PATH=C:\\path\\to\\tshark.exe    # Windows"
    )


FRAME_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
]

DIAMETER_SCALAR_FIELDS = [
    "diameter.Session-Id",
    "diameter.cmd.code",
    "diameter.flags.request",
    "diameter.CC-Request-Type",
    "diameter.Called-Station-Id",
    "diameter.3GPP-Charging-Characteristics",
    "diameter.3GPP-RAT-Type",
    "diameter.applicationId",
    "diameter.Result-Code",
    "diameter.Experimental-Result-Code",
    "diameter.Origin-Host",
    "diameter.Origin-Realm",
    "diameter.Destination-Host",
    "diameter.Destination-Realm",
    "diameter.hopbyhopid",
    "diameter.endtoendid",
    "diameter.Framed-IP-Address",
    "diameter.Framed-IP-Address.IPv4",
    "diameter.Framed-IPv6-Prefix",
]


DIAMETER_REPEATING_FIELDS = [
    "diameter.Subscription-Id-Data",
    "diameter.Subscription-Id-Type",
]


DIAMETER_FLAG_FIELDS = [
    "diameter.flags.request",
    "diameter.flags.proxyable",
    "diameter.flags.error",
    "diameter.flags.T",
]


DIAMETER_BANDWIDTH_FIELDS = [
    "diameter.Max-Requested-Bandwidth-UL",
    "diameter.Max-Requested-Bandwidth-DL",
]


def _dedupe(seq):
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


ALL_FIELDS = _dedupe(
    FRAME_FIELDS
    + DIAMETER_SCALAR_FIELDS
    + DIAMETER_REPEATING_FIELDS
    + DIAMETER_FLAG_FIELDS
    + DIAMETER_BANDWIDTH_FIELDS
)

INDEX_FIELDS = _dedupe(
    [
        "diameter.Session-Id",
        "diameter.Framed-IP-Address",
        "diameter.Framed-IP-Address.IPv4",
        "diameter.Framed-IPv6-Prefix",
        "diameter.Subscription-Id-Data",
        "diameter.Subscription-Id-Type",
    ]
)


def _first(value):
    if value is None or value == "":
        return None
    return value.split("|")[0]


_MESSAGE_COUNT_ANCHOR_FIELDS = ("diameter.Session-Id", "diameter.cmd.code")


def _split_values(value):
    if value is None or value == "":
        return []
    return value.split("|")


def _message_count(row):
    counts = [
        len(_split_values(row.get(field_name)))
        for field_name in _MESSAGE_COUNT_ANCHOR_FIELDS
        if field_name in row
    ]
    counts = [c for c in counts if c > 0]
    return max(counts) if counts else 1


def _at(value, index):
    parts = _split_values(value)
    if index >= len(parts):
        return None
    piece = parts[index]
    return piece if piece != "" else None


def _row_at(row, index):
    return {field_name: _at(value, index) for field_name, value in row.items()}


def build_packet_dict(row, index=0):
    sub_row = _row_at(row, index)

    command = sub_row.get("diameter.cmd.code")
    request_flag = sub_row.get("diameter.flags.request")

    flags = extract_diameter_flags(sub_row)
    bandwidth = extract_bandwidth_fields(sub_row)

    src = row.get("ip.src") or row.get("ipv6.src") or None
    dst = row.get("ip.dst") or row.get("ipv6.dst") or None

    return {
        "session": sub_row.get("diameter.Session-Id"),
        "subscription_id": _first(row.get("diameter.Subscription-Id-Data")),
        "subscription_type": _first(row.get("diameter.Subscription-Id-Type")),
        "ipv4": sub_row.get("diameter.Framed-IP-Address.IPv4") or sub_row.get("diameter.Framed-IP-Address"),
        "ipv6": sub_row.get("diameter.Framed-IPv6-Prefix"),
        "request_type": sub_row.get("diameter.CC-Request-Type"),
        "called_station_id": sub_row.get("diameter.Called-Station-Id"),
        "charging_characteristics": sub_row.get("diameter.3GPP-Charging-Characteristics"),
        "rat_type": sub_row.get("diameter.3GPP-RAT-Type"),
        "command": command,
        "command_name": command_family(command),
        "message_type": message_type(command, request_flag),
        "request_flag": request_flag,
        "application_id": sub_row.get("diameter.applicationId"),
        "result_code": sub_row.get("diameter.Result-Code"),
        "experimental_result_code": sub_row.get("diameter.Experimental-Result-Code"),
        "origin_host": sub_row.get("diameter.Origin-Host"),
        "origin_realm": sub_row.get("diameter.Origin-Realm"),
        "destination_host": sub_row.get("diameter.Destination-Host"),
        "destination_realm": sub_row.get("diameter.Destination-Realm"),
        "hop_by_hop": sub_row.get("diameter.hopbyhopid"),
        "end_to_end": sub_row.get("diameter.endtoendid"),
        "time": row.get("frame.time_epoch"),
        "src": src,
        "dst": dst,
        "length": row.get("frame.len"),
        "number": row.get("frame.number"),
        "flags": flags,
        "bandwidth": bandwidth,
    }


def build_packet_dicts(row):
    return [build_packet_dict(row, index) for index in range(_message_count(row))]


def build_index_dict(row, index=0):
    sub_row = _row_at(row, index)
    return {
        "session": sub_row.get("diameter.Session-Id"),
        "ipv4": sub_row.get("diameter.Framed-IP-Address.IPv4") or sub_row.get("diameter.Framed-IP-Address"),
        "ipv6": sub_row.get("diameter.Framed-IPv6-Prefix"),
        "subscription_id": _first(row.get("diameter.Subscription-Id-Data")),
        "subscription_type": _first(row.get("diameter.Subscription-Id-Type")),
    }


def build_index_dicts(row):
    return [build_index_dict(row, index) for index in range(_message_count(row))]


def _session_display_filter(session_ids):
    clauses = " or ".join(
        'diameter.Session-Id=="{}"'.format(str(sid).replace('"', '\\"'))
        for sid in session_ids
    )
    return f"diameter && ({clauses})"


def _run_tshark_fields(filename, fields, display_filter, progress_callback=None, tshark_path=None):
    tshark_path = tshark_path or resolve_tshark_path()

    cmd = [
        tshark_path,
        "-n",
        "-r", filename,
        "-Y", display_filter,
        "-T", "fields",
    ]
    for field in fields:
        cmd += ["-e", field]
    cmd += [
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "occurrence=a",
        "-E", "aggregator=|",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    count = 0
    header = None

    try:
        reader = csv.reader(proc.stdout, delimiter="\t")
        header = next(reader, None)

        if header is not None:
            for row_values in reader:
                count += 1

                if count % 1000 == 0:
                    if progress_callback:
                        progress_callback(count)

                yield dict(zip(header, row_values))

        if progress_callback:
            progress_callback(count)

    finally:
        proc.stdout.close()
        stderr_output = proc.stderr.read()
        proc.stderr.close()
        return_code = proc.wait()

        if return_code != 0:
            raise RuntimeError(
                f"tshark exited with code {return_code} while reading "
                f"{filename}: {stderr_output.strip()}"
            )

        if header is None:
            raise RuntimeError(
                f"tshark produced no output header while reading {filename} "
                "(no diameter packets, or a field name in ALL_FIELDS is wrong "
                "— check with `tshark -G fields | grep -i diameter`)"
            )


def read_packets(filename, progress_callback=None, tshark_path=None, session_ids=None):
    display_filter = "diameter"
    if session_ids:
        display_filter = _session_display_filter(session_ids)

    for row in _run_tshark_fields(filename, ALL_FIELDS, display_filter, progress_callback, tshark_path):
        yield from build_packet_dicts(row)


def read_session_index_rows(filename, progress_callback=None, tshark_path=None):
    for row in _run_tshark_fields(filename, INDEX_FIELDS, "diameter", progress_callback, tshark_path):
        yield from build_index_dicts(row)