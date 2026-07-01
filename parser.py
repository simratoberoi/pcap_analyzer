import pyshark


def get_field(layer, field):
    return getattr(layer, field, None)


def read_packets(filename):

    capture = pyshark.FileCapture(
        filename,
        tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark"
    )

    count = 0

    try:
        for packet in capture:

            count += 1

            if count % 1000 == 0:
                print(f"Processed {count} packets")

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

            yield {
                "session": get_field(d, "session_id"),
                "subscription_id": get_field(d, "subscription_id_data"),
                "subscription_type": get_field(d, "subscription_id_type"),
                "ipv4": get_field(d, "framed_ip_address"),
                "ipv6": get_field(d, "framed_ipv6_prefix"),
                "command": get_field(d, "cmd_code"),
                "request_flag": get_field(d, "flags_request"),
                "application_id": get_field(d, "application_id"),
                "result_code": get_field(d, "result_code"),
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
            }

    finally:
        capture.close()