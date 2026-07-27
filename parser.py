import csv
import subprocess

from diameter_utils import (
    command_family,
    extract_bandwidth_fields,
    extract_diameter_flags,
    message_type,
)

TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"


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


def _first(value):
    if value is None or value == "":
        return None
    return value.split("|")[0]


def _first_of(row, *field_names):
    for field_name in field_names:
        value = _first(row.get(field_name))
        if value:
            return value
    return None


def build_packet_dict(row):

    command = _first(row.get("diameter.cmd.code"))
    request_flag = _first(row.get("diameter.flags.request"))

    flags = extract_diameter_flags(row)
    bandwidth = extract_bandwidth_fields(row)

    src = row.get("ip.src") or row.get("ipv6.src") or None
    dst = row.get("ip.dst") or row.get("ipv6.dst") or None

    return {
        "session": _first(row.get("diameter.Session-Id")),
        "subscription_id": _first(row.get("diameter.Subscription-Id-Data")),
        "subscription_type": _first(row.get("diameter.Subscription-Id-Type")),
        "ipv4": _first_of(row, "diameter.Framed-IP-Address.IPv4", "diameter.Framed-IP-Address"),
        "ipv6": _first(row.get("diameter.Framed-IPv6-Prefix")),
        "request_type": _first(row.get("diameter.CC-Request-Type")),
        "called_station_id": _first(row.get("diameter.Called-Station-Id")),
        "charging_characteristics": _first(row.get("diameter.3GPP-Charging-Characteristics")),
        "rat_type": _first(row.get("diameter.3GPP-RAT-Type")),
        "command": command,
        "command_name": command_family(command),
        "message_type": message_type(command, request_flag),
        "request_flag": request_flag,
        "application_id": _first(row.get("diameter.applicationId")),
        "result_code": _first(row.get("diameter.Result-Code")),
        "experimental_result_code": _first(row.get("diameter.Experimental-Result-Code")),
        "origin_host": _first(row.get("diameter.Origin-Host")),
        "origin_realm": _first(row.get("diameter.Origin-Realm")),
        "destination_host": _first(row.get("diameter.Destination-Host")),
        "destination_realm": _first(row.get("diameter.Destination-Realm")),
        "hop_by_hop": _first(row.get("diameter.hopbyhopid")),
        "end_to_end": _first(row.get("diameter.endtoendid")),
        "time": row.get("frame.time_epoch"),
        "src": src,
        "dst": dst,
        "length": row.get("frame.len"),
        "number": row.get("frame.number"),
        "flags": flags,
        "bandwidth": bandwidth,
    }


def read_packets(filename, progress_callback=None):
    cmd = [
        TSHARK_PATH,
        "-n",
        "-r", filename,
        "-Y", "diameter",
        "-T", "fields",
    ]
    for field in ALL_FIELDS:
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
                    print(f"Processed {count} packets")
                    if progress_callback:
                        progress_callback(count)

                row = dict(zip(header, row_values))
                yield build_packet_dict(row)

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