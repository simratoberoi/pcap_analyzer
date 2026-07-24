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
| `tool_core.py`     | Core filtering / session-resolution / output-formatting logic   |
| `parser.py`        | Reads packets from a capture via pyshark/tshark                 |
| `diameter_utils.py`| Diameter AVP and command-code helpers                           |
| `manager.py`       | Groups packets into sessions                                    |

## Prerequisites

1. **Python 3.9+**
2. **Wireshark / tshark installed on your machine.** `pyshark` is just a
   Python wrapper around the `tshark` command-line tool - it does not parse
   captures itself, so tshark must be installed separately:
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
   path above**, open `parser.py` and change the `tshark_path` argument
   passed to `pyshark.FileCapture(...)` to point at your `tshark` binary
   (or find it with `which tshark` / `where tshark`). Without this, both
   the UI and CLI will fail to read any capture.

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
| `--limit`        | Max matched requests for a `--ResultCode` search (default 50, `0` = no limit) |

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

- **`TSharkNotFoundException` / similar errors on startup** - `tshark_path`
  in `parser.py` doesn't point to a valid `tshark` binary on your system;
  see step 3 under Prerequisites.
- **No matching packets found** - double check the capture actually
  contains Diameter traffic (a `display_filter="diameter"` is applied
  under the hood), and that the ID/IP you're filtering on matches a value
  present in the capture exactly.
- **Streamlit UI errors about `st.status` or `st.container(key=...)`** -
  your installed Streamlit version predates those features; upgrade with
  `pip install -U streamlit` (see `requirements.txt` for the minimum
  version).