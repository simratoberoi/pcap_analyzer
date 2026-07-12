import os
import tempfile
from html import escape
from typing import Optional

import streamlit as st

from tool_core import build_output_text, load_sessions, resolve_selected_sessions


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

/* ---------- Headings ---------- */

h1,h2,h3,h4,h5,h6,
.panel-title{
    color:rgb(38,39,48) !important;
}

/* ---------- Button ---------- */

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

uploaded_file = None
filter_type = None
filter_value = ""
run_analysis = False

input_col, _ = st.columns([1.2, 0.8], gap="large")

with input_col:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='panel-title'>Input</div>", unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "Upload file",
        type=None,
        label_visibility="collapsed",
    )

    filter_type = st.selectbox(
        "Filter by",
        [
            "Session ID",
            "Subscription ID",
            "Framed IP Address",
            "IPv6 Address",
        ],
        label_visibility="collapsed",
    )

    filter_value = st.text_input(
        "Value",
        placeholder="Enter filter value",
        label_visibility="collapsed",
    )

    run_analysis = st.button(
        "Analyze",
        use_container_width=True,
    )

    st.markdown("</div>", unsafe_allow_html=True)

output_text = ""

if run_analysis:
    if not uploaded_file:
        st.error("Upload a file first.")
    elif not filter_value.strip():
        st.error("Enter a filter value.")
    else:
        suffix = os.path.splitext(uploaded_file.name)[1]

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(uploaded_file.getbuffer())
            temp_path = temp_file.name

        try:
            sessions = load_sessions(temp_path)

            filter_kwargs: dict[str, Optional[str]] = {
                "session": None,
                "subscription": None,
                "ipv4": None,
                "ipv6": None,
            }

            value = filter_value.strip()

            if filter_type == "Session ID":
                filter_kwargs["session"] = value
            elif filter_type == "Subscription ID":
                filter_kwargs["subscription"] = value
            elif filter_type == "Framed IP Address":
                filter_kwargs["ipv4"] = value
            else:
                filter_kwargs["ipv6"] = value

            selected_sessions = resolve_selected_sessions(
                sessions,
                **filter_kwargs,
            )

            output_text = build_output_text(
                sessions,
                selected_sessions,
            )

        except Exception as exc:
            st.error(f"Unable to analyze file: {exc}")

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)

st.markdown("<div class='panel'>", unsafe_allow_html=True)
st.markdown("<div class='panel-title'>Output</div>", unsafe_allow_html=True)

if output_text:
    st.markdown(
        f"<div class='output-box'>{escape(output_text)}</div>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        "<div class='output-box'>The output will appear here after you analyze a file.</div>",
        unsafe_allow_html=True,
    )

st.markdown("</div>", unsafe_allow_html=True)