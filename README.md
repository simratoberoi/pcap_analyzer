# PCAP Analyzer

A tool for filtering and reading Diameter signalling captures (Gx/Gy/Rx/Sy, etc.)
from `.pcap` / `.pcapng` files - by Session ID, Subscription ID, IPv4/IPv6
address, or Result Code (optionally narrowed to a specific request-type
family such as CCR, STR, ASR, RAR, AA, SLR) - across one or more capture
files at once. Available both as a Streamlit web UI and a CLI.

## Project layout

| File               | Purpose                                                        |
|--------------------|------------------------------------------------------------------|
| `app.py`           | Streamlit web UI                                                |
| `analyzer.py`      | Command-line entry point                                        |
| `tool_core.py`     | Core filtering / session-resolution / output-formatting logic, plus the SQLite-backed session index and cache |
| `parser.py`        | Reads packets from a capture by invoking `tshark` directly (subprocess) |
| `diameter_utils.py`| Diameter AVP and command-code helpers                           |
| `manager.py`       | Groups packets into sessions                                    |

## How session indexing and caching work (RAM optimization)

Every run first builds a lightweight **session index** - one row per
session with just its Session-Id, IP(s), and Subscription-Id(s) - instead
of holding every packet from every file in memory at once. This index is
stored on disk in SQLite rather than in a Python dict/set, so indexing
hundreds of files or tens of GB of captures doesn't grow the process's RAM
with the size of the input:

- Each file is indexed into its own small SQLite DB, named by a content
  hash of the file. Re-running a different filter against the same
  file(s) - or re-uploading the same file later in the web UI - reuses
  that cached index instead of re-parsing with `tshark`.
- Per-file DBs are merged into one per-run SQLite DB (`session_id`,
  `session_ips`, `session_subs` tables, indexed on IP and Subscription-Id)
  that filters resolve against with plain indexed SQL queries, so
  resolving a filter never requires pulling the whole index into Python.
- Only the (typically much smaller) matching session set, and later the
  matching packets themselves, are ever materialized as Python objects -
  full packet data for non-matching sessions is never read into memory.
- The same per-run DB also records each file's earliest packet
  timestamp, which the output uses to sort multiple pcaps in
  chronological (capture) order - see below.
- Cache files live under a temp directory (`DEFAULT_CACHE_DIR` in
  `tool_core.py`, overridable via `--cache-dir` on the CLI) and are keyed
  by content hash, so they're safe to leave in place and reuse across
  runs; delete that directory any time to clear the cache.

## Output ordering

When more than one capture file is analyzed together, matched packets in
the output are sorted at two levels:

1. **Chronological order of the pcaps** - by each file's earliest packet
   timestamp (from the session index), so results read in real capture
   order regardless of upload/argument order or which file's `tshark`
   process happens to finish first.
2. **Packet number within that file** - packet numbers reset per file, so
   they're only meaningful as a tiebreaker within the same file, never
   across files.

## Prerequisites

1. **Python 3.9+**
2. **Wireshark / tshark installed on your machine.** `parser.py` invokes
   the `tshark` command-line tool directly (via `subprocess`) and parses
   its tab-separated field output - there's no Python wrapper library in
   between, so `tshark` must be installed and reachable at the path
   configured in `parser.py`:
   - **macOS:** install [Wireshark.app](https://www.wireshark.org/download.html).
     `tshark` ships inside it at
     `/Applications/Wireshark.app/Contents/MacOS/tshark`, which is the path
     `parser.py` is currently hardcoded to use.
   - **Windows:** install Wireshark from the same link. Note the install
     path for `tshark.exe` (typically
     `C:\Program Files\Wireshark\tshark.exe`).
   - **Linux:** install the `tshark` package (e.g. `sudo apt install
     tshark` on Debian/Ubuntu, `sudo dnf install wireshark-cli` on
     Fedora). It usually ends up on your `PATH` at `/usr/bin/tshark`.
3. **If you're not on macOS, or Wireshark isn't installed at the default
   path above**, open `parser.py` and change the `TSHARK_PATH` constant
   near the top of the file to point at your `tshark` binary (or find it
   with `which tshark` / `where tshark`). Without this, both the UI and
   CLI will fail to read any capture.

## Setup

```bash
# from the project folder
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Running the web UI

```bash
streamlit run app.py
```

This opens (or prints a link to) `http://localhost:8501` in your browser.
From there:
1. Upload one or more `.pcap`/`.pcapng` files.
2. Pick a filter type (Session ID, Subscription ID, Framed IP Address,
   IPv6 Address, Result Code, or List Subscription IDs) and enter a value
   (not needed for List Subscription IDs).
3. For Result Code searches, optionally cap the number of matches and/or
   narrow to a specific request-type chip (CCR, STR, ASR, RAR, AA, SLR).
4. Click **Analyze**. Progress ("Processed N packets") streams live while
   the file(s) are read, and the button is disabled until the run finishes
   so a second click can't start an overlapping run.

**List Subscription IDs** doesn't filter sessions at all - it scans every
session in the upload(s) and prints every unique Subscription ID seen,
along with its type and how many sessions each one appears in. Useful for
discovering which subscribers are present in a capture before filtering
down to one of them.

## Running the CLI

```bash
python analyzer.py <capture1.pcap> [capture2.pcap ...] [options]
```

**Options:**

| Flag                  | Description                                                        |
|-----------------------|----------------------------------------------------------------------|
| `--list-subscriptions`| List every unique Subscription ID in the capture(s) and exit (ignores other filters) |
| `--session`      | Filter by Session ID                                                |
| `--subscription` | Filter by Subscription ID                                           |
| `--ipv4`         | Filter by Framed IPv4 address                                       |
| `--ipv6`         | Filter by Framed IPv6 address                                       |
| `--ResultCode`   | Filter by Result Code                                                |
| `--RequestType`  | Used with `--ResultCode`; one of `CCR`, `STR`, `ASR`, `RAR`, `AA`, `SLR` |
| `--limit`        | Max matched requests for a `--ResultCode` search (unlimited by default, pass a positive number to cap it) |
| `--workers`      | Number of files to read in parallel (each spawns its own `tshark` process). Defaults to `min(number of files, CPU count)` |
| `--cache-dir`    | Directory used to cache each file's SQLite session index, keyed by content hash (default: a `pcap_analyzer_index_cache` folder under your system temp dir). Re-running a different filter against the same file(s) reuses the cache instead of re-parsing with `tshark` |
| `--no-cache`     | Disable the session-index cache and always re-parse with `tshark`. Also skips the per-file content hash (a full extra read of each file) - worth using for a large one-time batch over files you won't re-analyze |

**Example:**

```bash
python analyzer.py capture.pcap --ResultCode 5012 --RequestType CCR --limit 20
```

Multiple capture files can be passed at once and are analyzed together
(sessions with the same Session-Id across files are merged):

```bash
python analyzer.py capture1.pcap capture2.pcap --session abc123@example.com
```

To see every Subscription ID present in a capture (e.g. before deciding
which one to filter on):

```bash
python analyzer.py capture.pcap --list-subscriptions
```

## Troubleshooting

- **`FileNotFoundError` / `[Errno 2] No such file or directory` for tshark,
  or a `RuntimeError` saying tshark exited with a non-zero code** -
  `TSHARK_PATH` in `parser.py` doesn't point to a valid `tshark` binary on
  your system; see step 3 under Prerequisites.
- **`RuntimeError: tshark produced no output header`** - tshark ran but a
  field name in `parser.py`'s `ALL_FIELDS` list doesn't exist on your
  installed tshark version; check with `tshark -G fields | grep -i
  diameter`.
- **No matching packets found** - double check the capture actually
  contains Diameter traffic (a `display_filter="diameter"` is applied
  under the hood), and that the ID/IP you're filtering on matches a value
  present in the capture exactly.
- **Streamlit UI errors about `st.status` or `st.container(key=...)`** -
  your installed Streamlit version predates those features; upgrade with
  `pip install -U streamlit` (see `requirements.txt` for the minimum
  version).
- **`ModuleNotFoundError: No module named 'sqlite3'`** - your Python
  build was compiled without SQLite support (common on some minimal
  Linux installs). Install your distro's SQLite dev package (e.g.
  `libsqlite3-dev` on Debian/Ubuntu) and reinstall/rebuild Python; see
  `requirements.txt` for details. No `pip install` fixes this, since
  `sqlite3` is a standard-library module.
- **Results look stale after re-analyzing a file you edited in place** -
  the session-index cache is keyed by file content hash, so this
  shouldn't normally happen; if it does, delete the cache directory
  (default: a `pcap_analyzer_index_cache` folder under your system temp
  dir, or whatever you passed to `--cache-dir`) or re-run with
  `--no-cache`.