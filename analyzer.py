import os
import sys

import argparse

from tool_core import (
    DEFAULT_CACHE_DIR,
    DEFAULT_RESULT_CODE_LIMIT,
    build_subscription_ids_output,
    iter_output_lines,
    load_session_index,
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


def clear_progress_line():
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()


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
    parser.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help=(
            "Directory used to cache the lightweight session index for each "
            f"file, keyed by content hash (default: {DEFAULT_CACHE_DIR}). "
            "Re-running a different filter against the same file(s) reuses "
            "the cached index instead of re-parsing with tshark."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help=(
            "Disable the session-index cache and always re-parse with tshark. "
            "Also skips the per-file content hash entirely (a full extra read "
            "of each file) since a one-shot run has no cache entry to reuse — "
            "worth using for a large one-time batch over files you won't "
            "re-analyze."
        ),
    )

    args = parser.parse_args()

    limit = None if args.limit == 0 else args.limit
    cache_dir = None if args.no_cache else args.cache_dir

    progress_cb = make_cli_progress_callback()

    with load_session_index(
        args.pcap, progress_callback=progress_cb, max_workers=args.workers, cache_dir=cache_dir
    ) as session_index:
        clear_progress_line()

        if args.list_subscriptions:
            print(
                build_subscription_ids_output(
                    session_index,
                    filter_summary=f"Files = {', '.join(args.pcap)}",
                )
            )
            return

        selected_sessions = resolve_selected_sessions(
            session_index,
            session=args.session,
            subscription=args.subscription,
            ipv4=args.ipv4,
            ipv6=args.ipv6,
        )

        # Stream output line-by-line (and packet-block-by-block) instead of
        # building the whole rendered text in memory first. Matters once a
        # run's matched output itself gets into the hundreds of MB (large
        # corpora / broad filters) — the old build_output_text() approach
        # held one giant joined string in RAM before printing any of it.
        first_chunk = True
        for chunk in iter_output_lines(
            args.pcap,
            session_index,
            selected_sessions,
            result_code=args.ResultCode,
            limit=limit,
            filter_summary=build_filter_summary(args),
            command_filter=REQUEST_TYPE_ALIASES.get(args.RequestType),
            progress_callback=progress_cb,
            max_workers=args.workers,
        ):
            if first_chunk:
                clear_progress_line()
                first_chunk = False
            print(chunk)

        if first_chunk:
            clear_progress_line()


if __name__ == "__main__":
    main()