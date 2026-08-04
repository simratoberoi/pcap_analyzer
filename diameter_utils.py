import re
from functools import lru_cache
from typing import NamedTuple, Optional


class SubscriptionId(NamedTuple):
    """Lightweight stand-in for the old {"value": ..., "type": ...} dict.

    A NamedTuple has no per-instance __dict__, so a large batch of these
    (one or more per packet, across millions of packets) costs a fraction
    of what an equivalent list of small dicts costs. `.get()` is provided
    so existing call sites written for dict-like access (`sub.get("value")`)
    keep working unchanged.
    """

    value: str
    type: Optional[str] = None

    def get(self, key, default=None):
        return getattr(self, key, default)


COMMAND_METADATA = {
    "272": {
        "family": "Credit-Control",
        "request": "Credit-Control-Request",
        "answer": "Credit-Control-Answer",
    },
    "275": {
        "family": "Session-Termination",
        "request": "Session-Termination-Request",
        "answer": "Session-Termination-Answer",
    },
    "274": {
        "family": "Abort-Session",
        "request": "Abort-Session-Request",
        "answer": "Abort-Session-Answer",
    },
    "258": {
        "family": "Re-Auth",
        "request": "Re-Auth-Request",
        "answer": "Re-Auth-Answer",
    },
    "265": {
        "family": "AA",
        "request": "AA-Request",
        "answer": "AA-Answer",
    },
    "8388635": {
        "family": "Spending-Limit",
        "request": "Spending-Limit-Request",
        "answer": "Spending-Limit-Answer",
    },
}

SUPPORTED_RESULT_COMMANDS = set(COMMAND_METADATA)

FLAG_LABELS = {
    "diameter.flags.request": "Request",
    "diameter.flags.proxyable": "Proxiable",
    "diameter.flags.error": "Error",
    "diameter.flags.T": "Potentially Retransmitted",
}

BANDWIDTH_FIELDS = {
    "diameter.Max-Requested-Bandwidth-UL": "Max-Requested-Bandwidth-UL",
    "diameter.Max-Requested-Bandwidth-DL": "Max-Requested-Bandwidth-DL",
    "diameter.Guaranteed-Bitrate-UL": "Guaranteed-Bitrate-UL",
    "diameter.Guaranteed-Bitrate-DL": "Guaranteed-Bitrate-DL",
}

REQUEST_FLAG_TRUE_VALUES = {"1", "true", "True"}
REQUEST_FLAG_FALSE_VALUES = {"0", "false", "False"}


def normalize_text(value):
    if value is None:
        return None

    return str(value).strip()


def is_request_flag_true(request_flag):
    return normalize_text(request_flag) in REQUEST_FLAG_TRUE_VALUES


def is_request_flag_false(request_flag):
    return normalize_text(request_flag) in REQUEST_FLAG_FALSE_VALUES


def normalize_match_value(value):
    text = normalize_text(value)
    if not text:
        return None

    numeric_tokens = re.findall(r"\d+", text)
    if numeric_tokens:
        return numeric_tokens[0]

    return text


def normalize_ip_value(value):
    text = normalize_text(value)
    if not text:
        return None

    text = text.split("/", 1)[0].strip()
    if not text:
        return None

    return text.lower()


def values_match(left, right):
    left_value = normalize_match_value(left)
    right_value = normalize_match_value(right)

    if left_value is None or right_value is None:
        return False

    return left_value == right_value


def normalize_command_code(value):
    command_code = normalize_text(value)
    if not command_code:
        return None

    return command_code


# These are derived from just a command code (and occasionally a request
# flag), so the same handful of inputs repeats across every packet in a
# capture. @lru_cache means we compute the family/label string once per
# distinct input and hand back the *same* cached string object on every
# subsequent packet, instead of re-deriving (and re-allocating) it up to
# millions of times.
@lru_cache(maxsize=None)
def command_family(command_code):
    command_code = normalize_command_code(command_code)
    if not command_code:
        return "Unknown"

    return COMMAND_METADATA.get(command_code, {}).get("family", f"Command-{command_code}")


@lru_cache(maxsize=None)
def message_type(command_code, request_flag):
    command_code = normalize_command_code(command_code)
    if not command_code:
        return "Unknown"

    metadata = COMMAND_METADATA[command_code] if command_code in COMMAND_METADATA else None
    if not metadata:
        return "Unknown"

    if is_request_flag_true(request_flag):
        return metadata["request"]
    if is_request_flag_false(request_flag):
        return metadata["answer"]

    return metadata["request"]


@lru_cache(maxsize=None)
def command_code_display(command_code):
    command_code = normalize_command_code(command_code)
    if not command_code:
        return "Unknown"

    family = command_family(command_code)
    if family == f"Command-{command_code}":
        return command_code

    return f"{command_code} ({family})"


# NOTE: these used to take the whole tshark `row` dict and build a small
# dict of *every* packet's flags/bandwidth up front, even when a given
# search never displays them. Packet now stores only the raw scalar
# fields (request_flag, proxyable, error_flag, ..., bandwidth_ul/dl) and
# calls these to assemble the display dict lazily, only when a packet is
# actually being formatted for output.
def build_flags_dict(request_flag=None, proxyable=None, error=None, retransmitted=None):
    flags = {}
    if request_flag not in (None, ""):
        flags[FLAG_LABELS["diameter.flags.request"]] = request_flag
    if proxyable not in (None, ""):
        flags[FLAG_LABELS["diameter.flags.proxyable"]] = proxyable
    if error not in (None, ""):
        flags[FLAG_LABELS["diameter.flags.error"]] = error
    if retransmitted not in (None, ""):
        flags[FLAG_LABELS["diameter.flags.T"]] = retransmitted
    return flags


def build_bandwidth_dict(max_ul=None, max_dl=None):
    bandwidth_fields = {}
    if max_ul not in (None, ""):
        bandwidth_fields["Max-Requested-Bandwidth-UL"] = max_ul
    if max_dl not in (None, ""):
        bandwidth_fields["Max-Requested-Bandwidth-DL"] = max_dl
    return bandwidth_fields


def is_supported_result_command(command_code):
    return normalize_command_code(command_code) in SUPPORTED_RESULT_COMMANDS