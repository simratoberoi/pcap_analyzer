import pyshark

from diameter_utils import (
    command_family,
    extract_bandwidth_fields,
    extract_diameter_flags,
    extract_layer_fields,
    message_type,
)


def get_field(layer, field):
    return getattr(layer, field, None)


def read_packets(filename, progress_callback=None):

    capture = pyshark.FileCapture(
    filename,
    tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark",
    display_filter="diameter"
    )

    count = 0

    try:
        for packet in capture:

            count += 1

            if count % 1000 == 0:
                print(f"Processed {count} packets")
                if progress_callback:
                    progress_callback(count)

            if not hasattr(packet, "diameter"):
                continue

            d = packet.diameter

            src = None
            dst = None

            if hasattr(packet, "ip"):
                src = packet.ip.src
                dst = packet.ip.dst

            elif hasattr(packet, "ipv6"):
                src = packet.ipv6.src
                dst = packet.ipv6.dst

            command = extract_layer_fields(d, ["cmd_code"])
            request_flag = extract_layer_fields(d, ["flags_request"])

            bandwidth = extract_bandwidth_fields(d)
            flags = extract_diameter_flags(d)

            yield {
                "session": get_field(d, "session_id"),
                "subscription_id": get_field(d, "subscription_id_data"),
                "subscription_type": get_field(d, "subscription_id_type"),
                "ipv4": extract_layer_fields(d, ["framed_ip_address_ipv4", "framed_ip_address"]),
                "ipv6": extract_layer_fields(d, ["framed_ipv6_prefix_ipv6", "framed_ipv6_prefix"]),
                "request_type": get_field(d, "cc_request_type"),
                "called_station_id": get_field(d, "called_station_id"),
                "charging_characteristics": get_field(d, "3gpp_charging_characteristics"),
                "rat_type": get_field(d, "3gpp_rat_type"),
                "command": command,
                "command_name": command_family(command),
                "message_type": message_type(command, request_flag),
                "request_flag": request_flag,
                "application_id": get_field(d, "application_id"),
                "result_code": get_field(d, "result_code"),
                "experimental_result_code": get_field(d, "experimental_result_code"),
                "origin_host": get_field(d, "origin_host"),
                "origin_realm": get_field(d, "origin_realm"),
                "destination_host": get_field(d, "destination_host"),
                "destination_realm": get_field(d, "destination_realm"),
                "hop_by_hop": get_field(d, "hop_by_hop_id"),
                "end_to_end": get_field(d, "end_to_end_id"),
                "time": packet.sniff_timestamp,
                "src": src,
                "dst": dst,
                "length": packet.length,
                "number": packet.number,
                "flags": flags,
                "bandwidth": {
                    **bandwidth,
                    "Max-Requested-Bandwidth-UL": get_field(d, "max_requested_bandwidth_ul"),
                    "Max-Requested-Bandwidth-DL": get_field(d, "max_requested_bandwidth_dl"),
                },
            }

        if progress_callback:
            progress_callback(count)

    finally:
        capture.close()