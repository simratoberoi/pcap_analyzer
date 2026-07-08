import argparse
from collections import defaultdict

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


def request_type_label(pkt):
    request_type = str(pkt.get("request_type")) if pkt.get("request_type") is not None else None

    mapping = {
        "1": "Initial",
        "2": "Update",
        "3": "Termination",
    }

    return mapping.get(request_type, request_type or "Unknown")


session_ips = defaultdict(set)
session_subscriptions = defaultdict(set)

for session_id, packets in sessions.items():
    for pkt in packets:
        if pkt.get("ipv4"):
            session_ips[session_id].add(pkt["ipv4"])
        if pkt.get("ipv6"):
            session_ips[session_id].add(pkt["ipv6"])
        if pkt.get("subscription_id"):
            session_subscriptions[session_id].add(pkt["subscription_id"])


selected_sessions = set()

if args.session:
    selected_sessions.add(args.session)
    target_ips = session_ips.get(args.session, set())
    for session_id, ips in session_ips.items():
        if ips & target_ips:
            selected_sessions.add(session_id)

if args.subscription:
    target_sessions = {
        session_id
        for session_id, subscriptions in session_subscriptions.items()
        if args.subscription in subscriptions
    }
    selected_sessions.update(target_sessions)

    target_ips = set()
    for session_id in target_sessions:
        target_ips.update(session_ips.get(session_id, set()))

    for session_id, ips in session_ips.items():
        if ips & target_ips:
            selected_sessions.add(session_id)

if args.ipv4 or args.ipv6:
    target_ip = args.ipv4 or args.ipv6
    target_sessions = {
        session_id
        for session_id, ips in session_ips.items()
        if target_ip in ips
    }
    selected_sessions.update(target_sessions)


def matches(pkt):
    if selected_sessions:
        return pkt["session"] in selected_sessions
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
        print(f"Request Type       : {request_type_label(pkt)}")
        print(f"Called Station Id  : {pkt['called_station_id']}")
        print(f"3GPP Charging Chars: {pkt['charging_characteristics']}")
        print(f"RAT Type           : {pkt['rat_type']}")

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