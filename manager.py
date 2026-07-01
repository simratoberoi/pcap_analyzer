from collections import defaultdict


def group_by_session(packet_stream):

    sessions = defaultdict(list)

    for packet in packet_stream:

        if packet["session"] is not None:
            sessions[packet["session"]].append(packet)

    return sessions