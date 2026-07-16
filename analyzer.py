import argparse

from tool_core import DEFAULT_RESULT_CODE_LIMIT, build_output_text, load_sessions, resolve_selected_sessions


def build_filter_summary(args):
    parts = []
    if args.session:
        parts.append(f"Session ID = {args.session}")
    if args.subscription:
        parts.append(f"Subscription ID = {args.subscription}")
    if args.ipv4:
        parts.append(f"IPv4 = {args.ipv4}")
    if args.ipv6:
        parts.append(f"IPv6 = {args.ipv6}")
    if args.ResultCode:
        parts.append(f"Result Code = {args.ResultCode}")

    return ", ".join(parts) if parts else None


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap")
    parser.add_argument("--session")
    parser.add_argument("--subscription")
    parser.add_argument("--ipv4")
    parser.add_argument("--ipv6")
    parser.add_argument("--ResultCode")
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_RESULT_CODE_LIMIT,
        help=(
            "Max number of matched requests to return for a --ResultCode search. "
            f"Default is {DEFAULT_RESULT_CODE_LIMIT}. Pass 0 for no limit."
        ),
    )

    args = parser.parse_args()

    # Treat --limit 0 as "no limit"
    limit = None if args.limit == 0 else args.limit

    sessions = load_sessions(args.pcap)
    selected_sessions = resolve_selected_sessions(
        sessions,
        session=args.session,
        subscription=args.subscription,
        ipv4=args.ipv4,
        ipv6=args.ipv6,
    )

    print(
        build_output_text(
            sessions,
            selected_sessions,
            result_code=args.ResultCode,
            limit=limit,
            filter_summary=build_filter_summary(args),
        )
    )


if __name__ == "__main__":
    main()