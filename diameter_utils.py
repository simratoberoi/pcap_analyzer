import re


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
    "flags_request": "Request",
    "flags_proxiable": "Proxiable",
    "flags_error": "Error",
    "flags_potentially_retransmitted": "Potentially Retransmitted",
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


def command_family(command_code):
    command_code = normalize_command_code(command_code)
    if not command_code:
        return "Unknown"

    return COMMAND_METADATA.get(command_code, {}).get("family", f"Command-{command_code}")


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


def command_code_display(command_code):
    command_code = normalize_command_code(command_code)
    if not command_code:
        return "Unknown"

    family = command_family(command_code)
    if family == f"Command-{command_code}":
        return command_code

    return f"{command_code} ({family})"


def layer_field_names(layer):
    field_names = getattr(layer, "field_names", None)
    if field_names is None:
        return []

    return list(field_names)


def extract_layer_fields(layer, candidate_fields):
    for field_name in candidate_fields:
        value = getattr(layer, field_name, None)
        if value is not None:
            return value

    return None


def extract_diameter_flags(layer):
    flags = {}
    for field_name in layer_field_names(layer):
        if not field_name.startswith("flags_"):
            continue

        value = getattr(layer, field_name, None)
        if value is None:
            continue

        label = FLAG_LABELS.get(field_name)
        if label is None:
            label = field_name.removeprefix("flags_").replace("_", " ").title()

        flags[label] = value

    return flags


def extract_bandwidth_fields(layer):
    bandwidth_fields = {}
    for field_name in layer_field_names(layer):
        normalized_name = field_name.lower()
        if "bandwidth" not in normalized_name and "qos" not in normalized_name:
            continue

        value = getattr(layer, field_name, None)
        if value is None:
            continue

        label = field_name.replace("_", " ").title()
        bandwidth_fields[label] = value

    return bandwidth_fields


def is_supported_result_command(command_code):
    return normalize_command_code(command_code) in SUPPORTED_RESULT_COMMANDS