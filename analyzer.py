import argparse

from tool_core import build_output_text, load_sessions, resolve_selected_sessions


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap")
    parser.add_argument("--session")
    parser.add_argument("--subscription")
    parser.add_argument("--ipv4")
    parser.add_argument("--ipv6")
    parser.add_argument("--ResultCode")

    args = parser.parse_args()

    sessions = load_sessions(args.pcap)
    selected_sessions = resolve_selected_sessions(
        sessions,
        session=args.session,
        subscription=args.subscription,
        ipv4=args.ipv4,
        ipv6=args.ipv6,
        result_code= args.ResultCode
    )

    print(build_output_text(sessions, selected_sessions))


if __name__ == "__main__":
    main()