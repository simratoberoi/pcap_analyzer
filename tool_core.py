import hashlib
import os
import sqlite3
import tempfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from manager import group_by_session
from parser import read_packets, read_session_index_rows
from diameter_utils import (
    command_family,
    is_request_flag_false,
    is_request_flag_true,
    normalize_command_code,
    normalize_ip_value,
    normalize_match_value,
    normalize_text,
    values_match,
)


IST = timezone(timedelta(hours=5, minutes=30))

DEFAULT_RESULT_CODE_LIMIT = None


DEFAULT_CACHE_DIR = os.path.join(tempfile.gettempdir(), "pcap_analyzer_index_cache")

_CACHE_HASH_CHUNK_SIZE = 4 * 1024 * 1024
_INSERT_BATCH_SIZE = 20000


_FILE_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS session_ips (
    session_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    UNIQUE(session_id, ip)
);
CREATE TABLE IF NOT EXISTS session_subs (
    session_id TEXT NOT NULL,
    sub_norm TEXT NOT NULL,
    sub_value TEXT,
    sub_type TEXT,
    UNIQUE(session_id, sub_norm)
);
"""

_RUN_TABLES_SCHEMA = _FILE_INDEX_SCHEMA

_RUN_SECONDARY_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_session_ips_ip ON session_ips(ip);
CREATE INDEX IF NOT EXISTS idx_session_ips_session ON session_ips(session_id);
CREATE INDEX IF NOT EXISTS idx_session_subs_norm ON session_subs(sub_norm);
CREATE INDEX IF NOT EXISTS idx_session_subs_session ON session_subs(session_id);
"""

_STAGING_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_subs_staging (
    session_id TEXT,
    sub_norm TEXT,
    sub_value TEXT,
    sub_type TEXT
);
"""


def _file_cache_key(path):
    """Content hash of the file, so identical uploads/re-runs share a cache
    entry regardless of the (possibly throwaway) path they were read from."""
    hasher = hashlib.blake2b(digest_size=16)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CACHE_HASH_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _open_file_db(db_path):
    """Opens/creates one file's index DB. journal_mode=OFF (not MEMORY —
    see module docstring) since there's no crash-safety requirement: this
    file is only made visible to other processes via the atomic
    os.replace() in _build_file_index_db."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.executescript(_FILE_INDEX_SCHEMA)
    return conn


def _open_run_db(db_path):
    """Opens the per-run merged DB with tables only — secondary indexes
    are added afterward, once, by _create_run_indexes."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.executescript(_RUN_TABLES_SCHEMA)
    conn.executescript(_STAGING_SCHEMA)
    return conn


def _create_run_indexes(conn):
    conn.executescript(_RUN_SECONDARY_INDEXES)


def _build_file_index_db(path, db_path):
    """Streams read_session_index_rows() straight into a fresh SQLite file
    for `path`, in bounded batches — memory used here is O(batch size),
    never O(file size). Built under a temp name and atomically renamed into
    place so a crash mid-build can never leave a half-written cache entry
    that a later run would trust."""
    tmp_path = f"{db_path}.{os.getpid()}.building"
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    conn = _open_file_db(tmp_path)
    try:
        session_batch, ip_batch, sub_batch = [], [], []

        def flush():
            if session_batch:
                conn.executemany("INSERT OR IGNORE INTO sessions(session_id) VALUES (?)", session_batch)
                session_batch.clear()
            if ip_batch:
                conn.executemany(
                    "INSERT OR IGNORE INTO session_ips(session_id, ip) VALUES (?, ?)", ip_batch
                )
                ip_batch.clear()
            if sub_batch:
                conn.executemany(
                    """
                    INSERT INTO session_subs(session_id, sub_norm, sub_value, sub_type)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(session_id, sub_norm) DO UPDATE SET
                        sub_type = COALESCE(session_subs.sub_type, excluded.sub_type)
                    """,
                    sub_batch,
                )
                sub_batch.clear()

        pending = 0
        for row in read_session_index_rows(path):
            session_id = row.get("session")
            if not session_id:
                continue

            session_batch.append((session_id,))

            ipv4 = normalize_ip_value(row.get("ipv4"))
            if ipv4:
                ip_batch.append((session_id, ipv4))
            ipv6 = normalize_ip_value(row.get("ipv6"))
            if ipv6:
                ip_batch.append((session_id, ipv6))

            for sub in row.get("subscription_ids") or []:
                raw_value = sub.get("value")
                normalized_sub = normalize_match_value(raw_value)
                if not normalized_sub:
                    continue
                sub_batch.append(
                    (session_id, normalized_sub, normalize_text(raw_value), sub.get("type"))
                )

            pending += 1
            if pending >= _INSERT_BATCH_SIZE:
                flush()
                conn.commit()
                pending = 0

        flush()
        conn.commit()
    finally:
        conn.close()

    os.replace(tmp_path, db_path)
    return db_path


def _build_index_db_direct(path):
    """Same build as _build_file_index_db, but for the no-reuse case:
    skips the content hash (a full extra read of the file, for a cache
    entry that will never be looked up again) and writes straight to a
    unique scratch path."""
    fd, db_path = tempfile.mkstemp(prefix="pcap_analyzer_filedb_", suffix=".sqlite3")
    os.close(fd)
    os.remove(db_path)
    return _build_file_index_db(path, db_path)


def _build_or_get_cached_file_db(path, cache_dir, skip_cache):
    if skip_cache:
        return _build_index_db_direct(path)

    cache_key = _file_cache_key(path)
    db_path = os.path.join(cache_dir, f"{cache_key}.idx.sqlite3")
    if os.path.isfile(db_path):
        return db_path
    os.makedirs(cache_dir, exist_ok=True)
    return _build_file_index_db(path, db_path)


def _merge_file_dbs_into(run_conn, file_db_paths):
    """Loads every per-file DB's raw session_subs rows into a plain
    staging table (no lookups, no dedup — just accumulate), then resolves
    sub_type with a single GROUP BY pass at the very end. This replaces
    the old approach of running one correlated UPDATE + EXISTS per file,
    which re-scanned the run DB's (ever-growing) session_subs table once
    per file — O(files x rows). This version is O(rows) total, regardless
    of how many files are merged.

    sessions/session_ips dedup only ever needs a primary-key / unique-key
    check (no cross-row lookups), so those stay as simple INSERT OR
    IGNORE ... SELECT per file — that part was never the bottleneck.
    """
    
    for i, file_db_path in enumerate(file_db_paths):
        alias = f"f{i}"
        run_conn.execute("ATTACH DATABASE ? AS " + alias, (file_db_path,))
        try:
            run_conn.execute(
                f"INSERT OR IGNORE INTO sessions(session_id) "
                f"SELECT session_id FROM {alias}.sessions"
            )
            run_conn.execute(
                f"INSERT OR IGNORE INTO session_ips(session_id, ip) "
                f"SELECT session_id, ip FROM {alias}.session_ips"
            )
            run_conn.execute(
                f"INSERT INTO session_subs_staging(session_id, sub_norm, sub_value, sub_type) "
                f"SELECT session_id, sub_norm, sub_value, sub_type FROM {alias}.session_subs"
            )
            run_conn.commit()
        finally:
            run_conn.execute(f"DETACH DATABASE {alias}")

    
    run_conn.execute(
        """
        INSERT INTO session_subs(session_id, sub_norm, sub_value, sub_type)
        SELECT session_id, sub_norm, MIN(sub_value), MAX(sub_type)
        FROM session_subs_staging
        GROUP BY session_id, sub_norm
        """
    )
    run_conn.execute("DROP TABLE session_subs_staging")
    run_conn.commit()

    _create_run_indexes(run_conn)
    run_conn.commit()


class SessionIndexStore:
    """Query interface over the merged, on-disk, per-run SQLite session
    index. Every lookup is an indexed SQL query — resolving a filter never
    requires pulling the whole index into Python; only the (typically much
    smaller) matching session set does."""

    def __init__(self, conn, db_path):
        self._conn = conn
        self._db_path = db_path
        self._closed = False

    def __len__(self):
        return self.total_sessions()

    def total_sessions(self):
        return self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def sample_session_ids(self, limit=10):
        cur = self._conn.execute("SELECT session_id FROM sessions LIMIT ?", (limit,))
        return [row[0] for row in cur]

    def _sessions_with_ip(self, ip):
        cur = self._conn.execute("SELECT session_id FROM session_ips WHERE ip = ?", (ip,))
        return {row[0] for row in cur}

    def _sessions_with_subscription(self, sub_norm):
        cur = self._conn.execute("SELECT session_id FROM session_subs WHERE sub_norm = ?", (sub_norm,))
        return {row[0] for row in cur}

    def _sessions_sharing_ips_of(self, session_id):
        cur = self._conn.execute(
            """
            SELECT DISTINCT other.session_id
            FROM session_ips AS mine
            JOIN session_ips AS other ON other.ip = mine.ip
            WHERE mine.session_id = ?
            """,
            (session_id,),
        )
        return {row[0] for row in cur}

    def _sessions_sharing_ips_of_any(self, session_ids):
        if not session_ids:
            return set()
        placeholders = ",".join("?" for _ in session_ids)
        cur = self._conn.execute(
            f"""
            SELECT DISTINCT other.session_id
            FROM session_ips AS mine
            JOIN session_ips AS other ON other.ip = mine.ip
            WHERE mine.session_id IN ({placeholders})
            """,
            tuple(session_ids),
        )
        return {row[0] for row in cur}

    def resolve_selected_sessions(self, session=None, subscription=None, ipv4=None, ipv6=None):
        """See module-level docstring on the standalone resolve_selected_sessions
        wrapper below for the filter semantics — this is the SQL-backed
        implementation of the same rules."""

        if not (session or subscription or ipv4 or ipv6):
            return None

        selected_sessions = set()

        if session:
            session_id = str(session).strip()
            selected_sessions.add(session_id)
            selected_sessions |= self._sessions_sharing_ips_of(session_id)

        if subscription:
            normalized_sub = normalize_match_value(subscription)
            subscription_sessions = self._sessions_with_subscription(normalized_sub) if normalized_sub else set()
            selected_sessions |= subscription_sessions
            selected_sessions |= self._sessions_sharing_ips_of_any(subscription_sessions)

        if ipv4 or ipv6:
            target_ip = normalize_ip_value(ipv4 or ipv6)
            if target_ip:
                selected_sessions |= self._sessions_with_ip(target_ip)

        return selected_sessions

    def subscription_report(self):
        cur = self._conn.execute(
            """
            SELECT sub_norm, MIN(sub_value) AS value, MAX(sub_type) AS type, COUNT(DISTINCT session_id)
            FROM session_subs
            GROUP BY sub_norm
            ORDER BY sub_norm
            """
        )
        return [
            {
                "normalized": row[0],
                "value": row[1] if row[1] is not None else row[0],
                "type": row[2],
                "session_count": row[3],
            }
            for row in cur
        ]

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.close()
        finally:
            try:
                os.remove(self._db_path)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def load_session_index(paths, progress_callback=None, max_workers=None, cache_dir=DEFAULT_CACHE_DIR):

    if isinstance(paths, str):
        paths = [paths]

    run_db_fd, run_db_path = tempfile.mkstemp(prefix="pcap_analyzer_run_", suffix=".sqlite3")
    os.close(run_db_fd)
    os.remove(run_db_path)
    run_conn = _open_run_db(run_db_path)

    total_files = len(paths)
    if total_files == 0:
        _create_run_indexes(run_conn)
        run_conn.commit()
        return SessionIndexStore(run_conn, run_db_path)

    skip_cache = cache_dir is None
    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0
    file_db_paths = []

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_build_or_get_cached_file_db, path, cache_dir, skip_cache): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            file_db_paths.append(future.result())

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    _merge_file_dbs_into(run_conn, file_db_paths)  

    if skip_cache:
        for db_path in file_db_paths:
            try:
                os.remove(db_path)
            except OSError:
                pass

    return SessionIndexStore(run_conn, run_db_path)


def resolve_selected_sessions(session_index, session=None, subscription=None, ipv4=None, ipv6=None):
    
    return session_index.resolve_selected_sessions(
        session=session, subscription=subscription, ipv4=ipv4, ipv6=ipv6
    )


def build_subscription_ids_output(session_index, filter_summary=None):
    output_lines = ["Reading packets...", "", f"Found {len(session_index)} sessions"]

    if filter_summary:
        output_lines.append(f"Filter: {filter_summary}")

    output_lines.append("")

    subscriptions = session_index.subscription_report()

    if not subscriptions:
        output_lines.append("No subscription IDs found.")
        return "\n".join(output_lines)

    output_lines.append(f"Found {len(subscriptions)} unique Subscription ID(s):")
    output_lines.append("")

    for entry in subscriptions:
        type_label = entry["type"] if entry["type"] is not None else "Unknown"
        output_lines.append(
            f"Subscription ID: {entry['value']:<30} Type: {type_label:<10} Sessions: {entry['session_count']}"
        )

    return "\n".join(output_lines)


COMMAND_FILTER_CHOICES = [
    {"code": "272", "label": "Credit-Control-Request/Answer", "note": "Request received by PCRF"},
    {"code": "275", "label": "Session-Termination-Request/Answer", "note": "Request sent as well as received by PCRF"},
    {"code": "274", "label": "Abort-Session-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "258", "label": "Re-Auth-Request/Answer", "note": "Request sent by PCRF"},
    {"code": "265", "label": "AA-Request/Answer", "note": "Authentication-Authorization exchange"},
    {"code": "8388635", "label": "Spending-Limit-Request/Answer", "note": "Sy interface (OCS spending limit)"},
]


def request_type_label(pkt):
    request_type = str(pkt.get("request_type")) if pkt.get("request_type") is not None else None

    mapping = {
        "1": "Initial",
        "2": "Update",
        "3": "Termination",
    }

    if request_type is None:
        return "Unknown"

    return mapping.get(request_type, request_type)


def is_request_packet(pkt):
    return is_request_flag_true(pkt.get("request_flag"))


def is_answer_packet(pkt):
    return is_request_flag_false(pkt.get("request_flag"))


def _read_one_file_full(path, session_ids=None, source_file=None):
    return path, group_by_session(read_packets(path, session_ids=session_ids, source_file=source_file))


def load_full_sessions(paths, session_ids=None, progress_callback=None, max_workers=None, file_names=None):
    if isinstance(paths, str):
        paths = [paths]

    merged_sessions = defaultdict(list)
    total_files = len(paths)

    if total_files == 0:
        return merged_sessions

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _read_one_file_full, path, session_ids, (file_names or {}).get(path)
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            _, file_sessions = future.result()

            for session_id, packets in file_sessions.items():
                merged_sessions[session_id].extend(packets)

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    return merged_sessions


def _read_one_file_matches(path, session_ids, source_file=None):
    """Worker for the plain (non --ResultCode) dump path. Streams one
    file's packets — tshark itself is already filtering to `session_ids`,
    the same narrowed set load_full_sessions would use — sorts them
    locally by frame number, and returns just this file's matches. No
    merging with any other file's packets happens here or in the caller,
    so nothing beyond one file's worth of matches is ever alive in the
    parent process at once.
    """
    matches = list(read_packets(path, session_ids=session_ids, source_file=source_file))
    matches.sort(key=lambda pkt: int(pkt.number))
    return path, matches


def iter_full_session_matches_by_file(paths, session_ids, progress_callback=None, max_workers=None, file_names=None):

    if isinstance(paths, str):
        paths = [paths]

    total_files = len(paths)
    if total_files == 0:
        return

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _read_one_file_matches, path, session_ids, (file_names or {}).get(path)
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            _, matches = future.result()

            yield path, matches

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)


def _match_result_code_in_file(path, result_code, command_filter=None, limit=None, source_file=None):

    pending_requests = {}
    matches = []
    seen = set()
    matched_count = 0
    limit_reached = False

    for pkt in read_packets(path, source_file=source_file):
        if limit is not None and matched_count >= limit:
            limit_reached = True
            break

        key = (pkt.session, str(pkt.command), str(pkt.hop_by_hop))

        if is_request_packet(pkt):
            pending_requests[key] = pkt
            continue

        if not is_answer_packet(pkt):
            continue

        packet_code = pkt.experimental_result_code or pkt.result_code
        if not values_match(packet_code, result_code):
            continue

        request_pkt = pending_requests.pop(key, None)
        if request_pkt is None:
            continue

        if command_filter and normalize_command_code(request_pkt.command) != command_filter:
            continue

        unique = (request_pkt.session, request_pkt.number)
        if unique in seen:
            continue

        seen.add(unique)
        matched_count += 1
        matches.append(request_pkt)

    return path, matches, matched_count, limit_reached


def _stream_result_code_matches(
    paths,
    result_code,
    limit=None,
    command_filter=None,
    max_workers=None,
    progress_callback=None,
    file_names=None,
):
    result_code = normalize_text(result_code)
    command_filter = normalize_command_code(command_filter)

    if isinstance(paths, str):
        paths = [paths]

    total_files = len(paths)
    if total_files == 0:
        return [], {"matched_requests": 0, "limit_reached": False}

    max_workers = max_workers or min(total_files, os.cpu_count() or 4)
    completed = 0

    all_matches = []
    seen = set()
    any_limit_reached = False

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _match_result_code_in_file,
                path,
                result_code,
                command_filter=command_filter,
                limit=limit,
                source_file=(file_names or {}).get(path),
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            _, file_matches, _, file_limit_reached = future.result()

            for pkt in file_matches:
                unique = (pkt.session, pkt.number)
                if unique in seen:
                    continue
                seen.add(unique)
                all_matches.append(pkt)

            if file_limit_reached:
                any_limit_reached = True

            completed += 1
            if progress_callback:
                progress_callback(completed, total_files, path)

    all_matches.sort(key=lambda pkt: pkt.number)

    limit_reached = any_limit_reached
    if limit is not None and len(all_matches) > limit:
        all_matches = all_matches[:limit]
        limit_reached = True

    return all_matches, {"matched_requests": len(all_matches), "limit_reached": limit_reached}


def iter_result_code_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
    stats=None,
):

    result_code = normalize_text(result_code)
    if not result_code:
        return

    command_filter = normalize_command_code(command_filter)

    seen = set()
    matched_count = 0
    limit_reached = False
    matches = []

    for session_id, packets in sessions.items():
        if limit is not None and matched_count >= limit:
            limit_reached = True
            break

        if selected_sessions is not None and session_id not in selected_sessions:
            continue

        requests_by_key = {}
        for index, pkt in enumerate(packets):
            if not is_request_packet(pkt):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            requests_by_key[key] = index

        for pkt in packets:
            if not is_answer_packet(pkt):
                continue

            packet_code = ( pkt.get("experimental_result_code") or pkt.get("result_code"))

            if not values_match(packet_code, result_code):
                continue

            key = (
                str(pkt.get("command")),
                str(pkt.get("hop_by_hop")),
            )
            request_index = requests_by_key.get(key)
            if request_index is None:

                continue

            request_pkt = packets[request_index]

            if command_filter and normalize_command_code(request_pkt.get("command")) != command_filter:
                continue

            unique = (request_pkt.get("session"), request_pkt.get("number"))
            if unique in seen:
                continue

            if limit is not None and matched_count >= limit:
                limit_reached = True
                break

            seen.add(unique)
            matched_count += 1
            matches.append(request_pkt)

        if limit is not None and matched_count >= limit:
            limit_reached = True
            break
    matches.sort(key=lambda pkt: int(pkt["number"]))

    for pkt in matches:
        yield pkt

    if stats is not None:
        stats["matched_requests"] = matched_count
        stats["limit_reached"] = limit_reached


def iter_matching_packets(
    sessions,
    selected_sessions=None,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    command_filter=None,
    stats=None,
):
    if result_code:
        yield from iter_result_code_packets(
            sessions,
            selected_sessions,
            result_code=result_code,
            limit=limit,
            command_filter=command_filter,
            stats=stats,
        )
        return

    matched_packets = []

    for packets in sessions.values():
        for pkt in packets:
            if selected_sessions is not None and pkt["session"] not in selected_sessions:
                continue

            matched_packets.append(pkt)

    matched_packets.sort(key=lambda pkt: int(pkt["number"]))

    yield from matched_packets


def format_timestamp(timestamp):
    try:
        timestamp_value = float(timestamp)
    except (TypeError, ValueError):
        return str(timestamp)

    return datetime.fromtimestamp(timestamp_value, tz=timezone.utc).astimezone(IST).strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )


def format_packet(pkt):
    bandwidth = pkt.get("bandwidth") or {}
    flags = pkt.get("flags") or {}

    flag_lines = []
    if "Request" in flags:
        flag_lines.append(f"Request Flag       : {flags['Request']}")

    for flag_label, flag_value in flags.items():
        if flag_label == "Request":
            continue
        flag_lines.append(f"{flag_label:<18} : {flag_value}")

    bandwidth_lines = []
    for field_label, field_value in bandwidth.items():
        if field_value is None:
            continue
        bandwidth_lines.append(f"{field_label:<18} : {field_value}")

    subscription_ids = pkt.get("subscription_ids") or []
    subscription_lines = []
    if subscription_ids:
        for sub in subscription_ids:
            type_label = sub.get("type") if sub.get("type") is not None else "Unknown"
            subscription_lines.append(f"Subscription ID    : {sub.get('value')} (Type: {type_label})")
    else:
        subscription_lines.append(f"Subscription ID    : {pkt.get('subscription_id')}")
        subscription_lines.append(f"Subscription Type  : {pkt.get('subscription_type')}")

    lines = [
        "=" * 80,
        f"File               : {pkt.get('file')}",
        f"Packet Number      : {pkt['number']}",
        f"Timestamp          : {format_timestamp(pkt['time'])}",
        f"Session ID         : {pkt['session']}",
        *subscription_lines,
        f"IPv4 Address       : {pkt['ipv4']}",
        f"IPv6 Address       : {pkt['ipv6']}",
        f"Request Type       : {request_type_label(pkt)}",
        f"Called Station Id  : {pkt['called_station_id']}",
        f"3GPP Charging Chars: {pkt['charging_characteristics']}",
        f"RAT Type           : {pkt['rat_type']}",
        f"Command Name       : {command_family(pkt.get('command'))}",
        f"Message Type       : {pkt.get('message_type') or command_family(pkt.get('command'))}",
    ]

    if bandwidth_lines:
        lines.append("Bandwidth:")
        lines.extend(bandwidth_lines)

    lines.extend(
        [
        f"Source             : {pkt['src']}",
        f"Destination        : {pkt['dst']}",
        f"Length             : {pkt['length']}",
        f"Command Code       : {pkt['command']}",
    ]
    )

    lines.extend(flag_lines)

    lines.extend(
        [
        f"Application ID     : {pkt['application_id']}",
        f"Result Code        : {pkt['result_code']}",
        f"Origin Host        : {pkt['origin_host']}",
        f"Origin Realm       : {pkt['origin_realm']}",
        f"Destination Host   : {pkt['destination_host']}",
        f"Destination Realm  : {pkt['destination_realm']}",
        f"Hop-by-Hop ID      : {pkt['hop_by_hop']}",
        f"End-to-End ID      : {pkt['end_to_end']}",
        "-" * 80,
        ]
    )

    return "\n".join(lines)


def iter_output_lines(
    paths,
    session_index,
    selected_sessions,
    result_code=None,
    limit=DEFAULT_RESULT_CODE_LIMIT,
    filter_summary=None,
    command_filter=None,
    progress_callback=None,
    max_workers=None,
    file_names=None,
):

    total_sessions = len(session_index)

    if selected_sessions is not None and not selected_sessions and not result_code:
        yield "Reading packets..."
        yield ""
        yield f"Found {total_sessions} sessions"
        if filter_summary:
            yield f"Filter: {filter_summary}"
        yield ""
        yield "No matching packets found."
        return

    if result_code:
        stats = {}

        if selected_sessions is not None:
            if not selected_sessions:
                matches = []
            else:
                sessions = load_full_sessions(
                    paths,
                    session_ids=selected_sessions,
                    progress_callback=progress_callback,
                    max_workers=max_workers,
                    file_names=file_names,
                )
                matches = list(
                    iter_result_code_packets(
                        sessions,
                        selected_sessions,
                        result_code=result_code,
                        limit=limit,
                        command_filter=command_filter,
                        stats=stats,
                    )
                )
        else:
            matches, stats = _stream_result_code_matches(
                paths,
                result_code,
                limit=limit,
                command_filter=command_filter,
                max_workers=max_workers,
                progress_callback=progress_callback,
                file_names=file_names,
            )

        yield "Reading packets..."
        yield ""
        yield f"Found {total_sessions} sessions"
        if filter_summary:
            yield f"Filter: {filter_summary}"
        yield ""

        if matches:
            for pkt in matches:
                yield format_packet(pkt)
        else:
            yield "No matching packets found."

        if stats.get("limit_reached"):
            yield (
                f"(Result stopped at limit={limit} matched requests. "
                "Increase or disable the limit to see more.)"
            )
        return

    if selected_sessions is not None:
        yield "Reading packets..."
        yield ""
        yield f"Found {total_sessions} sessions"
        if filter_summary:
            yield f"Filter: {filter_summary}"
        yield ""

        found = False
        for _path, matches in iter_full_session_matches_by_file(
            paths,
            selected_sessions,
            progress_callback=progress_callback,
            max_workers=max_workers,
            file_names=file_names,
        ):
            for pkt in matches:
                found = True
                yield format_packet(pkt)

        if not found:
            yield "No matching packets found."
        return

    yield "Reading packets..."
    yield ""
    yield f"Found {total_sessions} sessions"
    if filter_summary:
        yield f"Filter: {filter_summary}"
    yield ""
    yield "First 10 Sessions:"
    yield ""
    for session_id in session_index.sample_session_ids(10):
        yield session_id


def build_output_text(*args, **kwargs):
    return "\n".join(iter_output_lines(*args, **kwargs))