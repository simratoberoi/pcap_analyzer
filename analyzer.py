import os
import sys

import argparse

from tool_core import (
    DEFAULT_RESULT_CODE_LIMIT,
    build_output_text,
    build_subscription_ids_output,
    load_sessions,
    resolve_selected_sessions,
)

REQUEST_TYPE_ALIASES = {
    "CCR": "272",
    "STR": "275",
    "ASR": "274",
    "RAR": "258",
    "AA": "265",
    "SLR": "8388635",
}

PROGRESS_BAR_WIDTH = 30


def make_cli_progress_callback():
    """Overall progress bar across ALL files. Files are now read in parallel
    worker processes (see tool_core.load_sessions), so progress is reported
    per completed file rather than per packet within the current file —
    there's no single "current file" once several are being read at once."""

    def progress_cb(completed, total, path):
        overall = completed / total

        pos = int(overall * PROGRESS_BAR_WIDTH)
        bar = "#" * pos + "-" * (PROGRESS_BAR_WIDTH - pos)
        sys.stdout.write(
            f"\r[{bar}] {overall * 100:5.1f}%  "
            f"{completed}/{total} files done (just finished: {os.path.basename(path)})".ljust(120)
        )
        sys.stdout.flush()

    return progress_cb


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
        if args.RequestType:
            parts.append(f"Request Type = {args.RequestType}")

    return ", ".join(parts) if parts else None


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap", nargs="+", help="One or more .pcap/.pcapng files to analyze together")
    parser.add_argument(
        "--list-subscriptions",
        action="store_true",
        help="List every unique Subscription ID found in the capture(s) and exit (ignores other filters).",
    )
    parser.add_argument("--session")
    parser.add_argument("--subscription")
    parser.add_argument("--ipv4")
    parser.add_argument("--ipv6")
    parser.add_argument("--ResultCode")
    parser.add_argument(
        "--RequestType",
        choices=list(REQUEST_TYPE_ALIASES),
        help=(
            "Only used together with --ResultCode. Further restricts matches to "
            "answers whose corresponding request is of this command family: "
            "CCR=Credit-Control-Request/Answer (received by PCRF), "
            "STR=Session-Termination-Request/Answer (sent as well as received by PCRF), "
            "ASR=Abort-Session-Request/Answer (sent by PCRF), "
            "RAR=Re-Auth-Request/Answer (sent by PCRF), "
            "AA=AA-Request/Answer (authentication-authorization exchange), "
            "SLR=Spending-Limit-Request/Answer (Sy interface, OCS spending limit)."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_RESULT_CODE_LIMIT,
        help=(
            "Max number of matching Requests to return for a --ResultCode search "
            "(each matched Answer's corresponding Request is printed, not the whole session). "
            "Unlimited by default — pass a positive number to cap it."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Number of files to read in parallel (each spawns its own tshark "
            "process). Defaults to min(number of files, CPU count). Lower this "
            "if reading many large files at once thrashes your machine."
        ),
    )

    args = parser.parse_args()

    limit = None if args.limit == 0 else args.limit

    progress_cb = make_cli_progress_callback()
    sessions = load_sessions(args.pcap, progress_callback=progress_cb, max_workers=args.workers)
    sys.stdout.write("\r" + " " * 120 + "\r")  # clear the progress line
    sys.stdout.flush()

    if args.list_subscriptions:
        print(
            build_subscription_ids_output(
                sessions,
                filter_summary=f"Files = {', '.join(args.pcap)}",
            )
        )
        return

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
            command_filter=REQUEST_TYPE_ALIASES.get(args.RequestType),
        )
    )


if __name__ == "__main__":
    main()