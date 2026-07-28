import os
import tempfile
from html import escape
from typing import Optional

import streamlit as st

from tool_core import (
    COMMAND_FILTER_CHOICES,
    DEFAULT_RESULT_CODE_LIMIT,
    build_output_text,
    build_subscription_ids_output,
    load_sessions,
    resolve_selected_sessions,
)


st.set_page_config(
    page_title="PCAP Analyzer",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>

/* Hide Streamlit header */
header[data-testid="stHeader"]{
    display:none;
}
#MainMenu{
    visibility:hidden;
}
footer{
    visibility:hidden;
}

/* ---------- File Uploader ---------- */

div[data-testid="stFileUploader"]{
    background:transparent;
    border:none;
    padding:0;
}

section[data-testid="stFileUploaderDropzone"]{
    background:#ffffff !important;
    border:1px solid #cfd8e6 !important;
    border-radius:16px !important;
    color:rgb(38,39,48) !important;
}

section[data-testid="stFileUploaderDropzone"] *{
    color:rgb(38,39,48) !important;
}

/* Upload button */

section[data-testid="stFileUploaderDropzone"] button{
    background:white !important;
    border:1px solid #cfd8e6 !important;
    color:rgb(38,39,48) !important;
}

/* ---------- Select Box ---------- */

div[data-baseweb="select"]{
    background:white !important;
}

div[data-baseweb="select"] > div{
    background:white !important;
    border:1px solid #cfd8e6 !important;
    border-radius:12px !important;
    min-height:54px;
}

div[data-baseweb="select"] *{
    color:rgb(38,39,48) !important;
}

/* ---------- Text Input ---------- */

div[data-testid="stTextInput"] input{
    background:white !important;
    border:1px solid #cfd8e6 !important;
    border-radius:12px !important;
    color:rgb(38,39,48) !important;
    box-shadow:none !important;
}

div[data-testid="stTextInput"] input:focus{
    border:1px solid #b9c8d8 !important;
    box-shadow:none !important;
}

/* ---------- Number Input ---------- */

div[data-testid="stNumberInput"] input{
    background:white !important;
    border:1px solid #cfd8e6 !important;
    border-radius:12px !important;
    color:rgb(38,39,48) !important;
    box-shadow:none !important;
}

/* ---------- Headings ---------- */

h1,h2,h3,h4,h5,h6,
.panel-title{
    color:rgb(38,39,48) !important;
}

/* ---------- Button (main CTA, e.g. Analyze) ---------- */

.stButton button{
    background:#4285F4;
    color:white;
    border:none;
    border-radius:10px;
    font-weight:600;
}

.stButton button:hover{
    background:#5b95f7;
}

/* ---------- Request-type filter chips ----------
   Scoped to the request-type-filters container only, so these never
   bleed into or get overridden by the main CTA button rule above.
   Uniform, subtle look regardless of which command is active; the
   active one gets a light tint instead of solid CTA-blue. */

.st-key-request_type_filters div[data-testid="stButton"] button{
    background:#ffffff !important;
    border:1px solid #cfd8e6 !important;
    color:rgb(90,99,116) !important;
    font-weight:500 !important;
    border-radius:8px !important;
    box-shadow:none !important;
}

.st-key-request_type_filters div[data-testid="stButton"] button:hover{
    background:#f3f6fb !important;
    border-color:#a9bcd6 !important;
    color:rgb(38,39,48) !important;
}

.st-key-request_type_filters div[data-testid="stButton"] button[kind="primary"]{
    background:#eaf1fd !important;
    border:1px solid #4285F4 !important;
    color:#1a56c4 !important;
    font-weight:600 !important;
}

.st-key-request_type_filters div[data-testid="stButton"] button[kind="primary"]:hover{
    background:#dde9fc !important;
    border-color:#3672db !important;
}

/* ---------- Output ---------- */

.output-box{
    background:#ffffff;
    border:1px solid #cfd8e6;
    border-radius:16px;
    padding:18px;
    max-height:720px;
    overflow-y:auto;
    white-space:pre-wrap;
    word-break:break-word;

    font-size:15px;
    font-family:Consolas, "Courier New", monospace;
    line-height:1.6;
    color:rgb(38,39,48);
}

/* Make every element inside output the same size */
.output-box,
.output-box *,
.output-box h1,
.output-box h2,
.output-box h3,
.output-box h4,
.output-box h5,
.output-box h6,
.output-box p,
.output-box span,
.output-box pre{
    font-size:15px !important;
    font-weight:400 !important;
    font-family:Consolas, "Courier New", monospace !important;
    line-height:1.6 !important;
    color:rgb(38,39,48) !important;
    margin:0 !important;
}

</style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<h1 style='margin-bottom:0.2rem;color:rgb(38,39,48);'>PCAP Analyzer</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div style='color:rgb(38,39,48);margin-bottom:1.2rem;'>Upload a capture, choose a filter, and view the CLI output in one place.</div>",
    unsafe_allow_html=True,
)

FILTER_PLACEHOLDER = "-- Select a filter --"

FILTER_OPTIONS = [
    FILTER_PLACEHOLDER,
    "Session ID",
    "Subscription ID",
    "Framed IP Address",
    "IPv6 Address",
    "Result Code",
    "List Subscription IDs",
]

NO_VALUE_FILTERS = {"List Subscription IDs"}

if "is_processing" not in st.session_state:
    st.session_state.is_processing = False
if "output_text" not in st.session_state:
    st.session_state.output_text = ""

uploaded_files = None
filter_type = None
filter_value = ""
result_limit = DEFAULT_RESULT_CODE_LIMIT
run_analysis = False

input_col, _ = st.columns([1.2, 0.8], gap="large")

with input_col:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='panel-title'>Input</div>", unsafe_allow_html=True)

    uploaded_files = st.file_uploader(
        "Upload file(s)",
        type=None,
        label_visibility="collapsed",
        accept_multiple_files=True,
        disabled=st.session_state.is_processing,
    )

    filter_type = st.selectbox(
        "Filter by",
        FILTER_OPTIONS,
        index=0,
        label_visibility="collapsed",
        disabled=st.session_state.is_processing,
    )

    if filter_type not in NO_VALUE_FILTERS:
        filter_value = st.text_input(
            "Value",
            placeholder="Enter filter value",
            label_visibility="collapsed",
            disabled=st.session_state.is_processing,
        )
    else:
        st.caption("No value needed — this lists every Subscription ID found in the upload(s).")

    if filter_type == "Result Code":
        result_limit = st.number_input(
            "Max matched requests (0 = no limit)",
            min_value=0,
            value=DEFAULT_RESULT_CODE_LIMIT,
            step=10,
            help=(
                "Result-code searches print each matching Answer's corresponding "
                "Request only - not the whole session. Cap how many Requests are "
                "returned, or set 0 for no cap."
            ),
            disabled=st.session_state.is_processing,
        )

        st.markdown(
            "<div style='color:rgb(38,39,48);margin:0.6rem 0 0.3rem;font-weight:600;'>"
            "Filter by request type</div>",
            unsafe_allow_html=True,
        )

        if "command_filter_choice" not in st.session_state:
            st.session_state.command_filter_choice = None

        with st.container(key="request_type_filters"):
            button_cols = st.columns(len(COMMAND_FILTER_CHOICES))
            for col, choice in zip(button_cols, COMMAND_FILTER_CHOICES):
                with col:
                    is_active = st.session_state.command_filter_choice == choice["code"]
                    if st.button(
                        choice["label"],
                        key=f"command_filter_btn_{choice['code']}",
                        help=choice["note"],
                        use_container_width=True,
                        type="primary" if is_active else "secondary",
                        disabled=st.session_state.is_processing,
                    ):
                        st.session_state.command_filter_choice = None if is_active else choice["code"]

        active_choice = next(
            (c for c in COMMAND_FILTER_CHOICES if c["code"] == st.session_state.command_filter_choice),
            None,
        )
        if active_choice:
            st.caption(f"Active: {active_choice['label']} — {active_choice['note']} (click again to clear)")

    run_analysis = st.button(
        "Analyze",
        use_container_width=True,
        disabled=st.session_state.is_processing,
    )

    st.markdown("</div>", unsafe_allow_html=True)

if run_analysis and not st.session_state.is_processing:
    st.session_state.output_text = ""
    if not uploaded_files:
        st.error("Upload at least one file first.")
    elif filter_type == FILTER_PLACEHOLDER:
        st.error("Select a filter type from the dropdown.")
    elif filter_type not in NO_VALUE_FILTERS and not filter_value.strip():
        st.error("Enter a filter value.")
    else:
        st.session_state.is_processing = True
        st.rerun()

if st.session_state.is_processing:
    temp_paths = []
    temp_path_to_name = {}

    try:
        for uploaded in uploaded_files:
            suffix = os.path.splitext(uploaded.name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                temp_file.write(uploaded.getbuffer())
                temp_path = temp_file.name
            temp_paths.append(temp_path)
            temp_path_to_name[temp_path] = uploaded.name

        with st.status("Reading packets...", expanded=True) as status:
            progress_bar = st.progress(0.0)
            total_files = len(temp_paths)
            progress_state = {"file_order": [], "current_path": None}
            SMOOTHING_K = 2000

            def progress_cb(count, path):
                if path != progress_state["current_path"]:
                    if path not in progress_state["file_order"]:
                        progress_state["file_order"].append(path)
                    progress_state["current_path"] = path

                completed_files = len(progress_state["file_order"]) - 1
                frac_within_current = count / (count + SMOOTHING_K)
                overall = (completed_files + frac_within_current) / total_files
                overall = min(overall, 0.999)

                name = temp_path_to_name.get(path, path)
                progress_bar.progress(
                    overall,
                    text=f"File {completed_files + 1}/{total_files} — {name}: {count} packets",
                )

            sessions = load_sessions(temp_paths, progress_callback=progress_cb)

            progress_bar.progress(1.0, text="Done reading all files")
            status.update(
                label=f"Done reading — found {len(sessions)} session(s) across {len(temp_paths)} file(s)",
                state="complete",
                expanded=False,
            )

            sessions = load_sessions(temp_paths, progress_callback=progress_cb)

            progress_bar.progress(1.0, text="Done reading all files")
            status.update(
                label=f"Done reading — found {len(sessions)} session(s) across {len(temp_paths)} file(s)",
                state="complete",
                expanded=False,
            )

        if filter_type == "List Subscription IDs":
            filter_summary = f"List Subscription IDs, Files = {', '.join(temp_path_to_name.values())}"

            st.session_state.output_text = build_subscription_ids_output(
                sessions,
                filter_summary=filter_summary,
            )

        else:
            filter_kwargs: dict[str, Optional[str]] = {
                "session": None,
                "subscription": None,
                "ipv4": None,
                "ipv6": None,
            }
            result_code = None

            value = filter_value.strip()

            if filter_type == "Session ID":
                filter_kwargs["session"] = value
            elif filter_type == "Subscription ID":
                filter_kwargs["subscription"] = value
            elif filter_type == "Framed IP Address":
                filter_kwargs["ipv4"] = value
            elif filter_type == "IPv6 Address":
                filter_kwargs["ipv6"] = value
            elif filter_type == "Result Code":
                result_code = value

            selected_sessions = resolve_selected_sessions(
                sessions,
                **filter_kwargs,
            )

            limit = None if result_limit == 0 else result_limit

            command_filter = None
            filter_summary = f"{filter_type} = {value}"
            if filter_type == "Result Code":
                active_choice = next(
                    (
                        c
                        for c in COMMAND_FILTER_CHOICES
                        if c["code"] == st.session_state.get("command_filter_choice")
                    ),
                    None,
                )
                if active_choice:
                    command_filter = active_choice["code"]
                    filter_summary += f", Request Type = {active_choice['label']}"

            filter_summary += f", Files = {', '.join(temp_path_to_name.values())}"

            st.session_state.output_text = build_output_text(
                sessions,
                selected_sessions,
                result_code=result_code,
                limit=limit,
                filter_summary=filter_summary,
                command_filter=command_filter,
            )

    except Exception as exc:
        st.session_state.output_text = ""
        st.error(f"Unable to analyze file(s): {exc}")

    finally:
        for temp_path in temp_paths:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        st.session_state.is_processing = False

    st.rerun()

st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='panel-title'>Output</div>", unsafe_allow_html=True)

if st.session_state.output_text:
    st.markdown(
        f"<div class='output-box'>{escape(st.session_state.output_text)}</div>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        "<div class='output-box'>The output will appear here after you analyze a file.</div>",
        unsafe_allow_html=True,
    )

st.markdown("</div>", unsafe_allow_html=True)