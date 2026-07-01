import argparse

from parser import read_packets
from manager import group_by_session


parser = argparse.ArgumentParser()

parser.add_argument("pcap")
parser.add_argument("--session")
parser.add_argument("--subscription")
parser.add_argument("--ipv4")
parser.add_argument("--ipv6")

args = parser.parse_args()

print("Reading packets...")

sessions = group_by_session(read_packets(args.pcap))

print(f"\nFound {len(sessions)} sessions")


def matches(pkt):
    if args.session and pkt["session"] != args.session:
        return False

    if args.subscription and pkt["subscription_id"] != args.subscription:
        return False

    if args.ipv4 and pkt["ipv4"] != args.ipv4:
        return False

    if args.ipv6 and pkt["ipv6"] != args.ipv6:
        return False

    return True


found = False

for packets in sessions.values():

    for pkt in packets:

        if not matches(pkt):
            continue

        found = True

        print("=" * 80)

        print(f"Packet Number      : {pkt['number']}")
        print(f"Timestamp          : {pkt['time']}")

        print(f"Session ID         : {pkt['session']}")
        print(f"Subscription ID    : {pkt['subscription_id']}")
        print(f"Subscription Type  : {pkt['subscription_type']}")

        print(f"IPv4 Address       : {pkt['ipv4']}")
        print(f"IPv6 Address       : {pkt['ipv6']}")

        print(f"Source             : {pkt['src']}")
        print(f"Destination        : {pkt['dst']}")
        print(f"Length             : {pkt['length']}")

        print(f"Command Code       : {pkt['command']}")
        print(f"Request Flag       : {pkt['request_flag']}")
        print(f"Application ID     : {pkt['application_id']}")
        print(f"Result Code        : {pkt['result_code']}")

        print(f"Origin Host        : {pkt['origin_host']}")
        print(f"Origin Realm       : {pkt['origin_realm']}")

        print(f"Destination Host   : {pkt['destination_host']}")
        print(f"Destination Realm  : {pkt['destination_realm']}")

        print(f"Hop-by-Hop ID      : {pkt['hop_by_hop']}")
        print(f"End-to-End ID      : {pkt['end_to_end']}")

        print("-" * 80)


if not found:

    if args.session or args.subscription or args.ipv4 or args.ipv6:
        print("\nNo matching packets found.")

    else:
        print("\nFirst 10 Sessions:\n")

        for sid in list(sessions.keys())[:10]:
            print(sid)