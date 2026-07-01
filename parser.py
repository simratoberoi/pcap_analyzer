import pyshark

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

            try:
                yield {
                    "session": packet.diameter.session_id,
                    "time": packet.sniff_timestamp,
                    "command": packet.diameter.cmd_code,
                    "src": packet.ip.src,
                    "dst": packet.ip.dst,
                }
            except AttributeError:
                pass

    finally:
        capture.close()