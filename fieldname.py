"""
Find the real pyshark field name for a target IP that Wireshark shows but
parser.py's 'framed_ip_address' attribute doesn't catch.

Usage:
    python find_ip_field.py /path/to/capture.pcap 10.80.84.235
"""
import sys

import pyshark

PCAP = sys.argv[1]
TARGET = sys.argv[2] if len(sys.argv) > 2 else "10.80.84.235"

capture = pyshark.FileCapture(
    PCAP,
    tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark",
    display_filter="diameter",
)

candidate_names = set()
exact_field_hits = []
count = 0

try:
    for packet in capture:
        count += 1
        if count % 1000 == 0:
            print(f"Scanned {count} packets...")

        if not hasattr(packet, "diameter"):
            continue

        d = packet.diameter
        field_names = list(getattr(d, "field_names", []) or [])

        # Collect every field whose name LOOKS ip/framed related, regardless
        # of whether it matches our target, so we can see the full landscape.
        for name in field_names:
            lname = name.lower()
            if "ip" in lname or "framed" in lname or "address" in lname:
                candidate_names.add(name)

        # Also directly check every field's VALUE against the target IP,
        # no matter what the field is named -- this catches vendor/grouped
        # AVPs with unexpected names.
        for name in field_names:
            value = getattr(d, name, None)
            if value is None:
                continue
            value_str = str(value).strip()
            if TARGET in value_str:
                exact_field_hits.append((packet.number, name, value_str))

finally:
    capture.close()

print(f"\nScanned {count} total diameter packets.\n")

print("All field names on the diameter layer that look IP/address-related "
      "(seen anywhere in the capture):")
for name in sorted(candidate_names):
    print(f"  - {name}")

print(f"\nFields whose VALUE actually contains {TARGET!r}:")
if not exact_field_hits:
    print("  (none found anywhere, under any field name)")
else:
    for pkt_number, name, value in exact_field_hits:
        print(f"  packet #{pkt_number}: field='{name}' value={value!r}")