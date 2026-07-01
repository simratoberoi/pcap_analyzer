import argparse

from parser import read_packets
from manager import group_by_session

parser = argparse.ArgumentParser()

parser.add_argument("pcap")
parser.add_argument("--session")

args = parser.parse_args()

print("Reading packets...")

sessions = group_by_session(read_packets(args.pcap))

print(f"Found {len(sessions)} sessions")

if args.session:

    if args.session not in sessions:
        print("Session not found")

    else:
        print(f"\nMessages for {args.session}\n")

        for pkt in sessions[args.session]:
            print(
                f"{pkt['time']} | "
                f"{pkt['command']} | "
                f"{pkt['src']} -> {pkt['dst']}"
            )

else:

    print("\nFirst 10 Sessions:\n")

    for sid in list(sessions.keys())[:10]:
        print(sid)