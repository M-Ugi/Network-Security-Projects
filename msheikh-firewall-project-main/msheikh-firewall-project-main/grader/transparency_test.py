import ipaddress
import random
import string
import random
import threading
import time
from grader_utility import *


def _single_tcp_transparency():
    localhost_network = ipaddress.ip_network("127.0.0.0/8")

    src_IP = bool_list_to_ip(
        randomize_bool_list_suffix(
            ip_to_bool_list(localhost_network.network_address),
            localhost_network.prefixlen
        )
    )
    dst_IP = bool_list_to_ip(
        randomize_bool_list_suffix(
            ip_to_bool_list(localhost_network.network_address),
            localhost_network.prefixlen
        )
    )

    src_port = random.randrange(1024, 65536)
    dst_port = random.randrange(1024, 65536)

    test_message = bytes(
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=100)),
        encoding='utf8'
    )

    pkt_adr_log = []
    time_log = []

    recv_thread = threading.Thread(
        target=tcp_listen,
        args=(str(dst_IP), dst_port, 1.0, pkt_adr_log, time_log)
    )
    recv_thread.start()

    time.sleep(0.5)

    tcp_send(str(src_IP), src_port, str(dst_IP), dst_port,
             [test_message], [0.0])

    recv_thread.join()

    if len(pkt_adr_log) == 0:
        return 0.0

    addr = pkt_adr_log[0][1]
    if addr != (str(src_IP), src_port):
        return 0.0

    sent = test_message.decode()
    received = "".join([t.decode() for (t, _) in pkt_adr_log])
    if sent != received:
        return 0.0

    return 1.0


def _single_udp_transparency():
    localhost_network = ipaddress.ip_network("127.0.0.0/8")

    src_IP = bool_list_to_ip(
        randomize_bool_list_suffix(
            ip_to_bool_list(localhost_network.network_address),
            localhost_network.prefixlen
        )
    )
    dst_IP = bool_list_to_ip(
        randomize_bool_list_suffix(
            ip_to_bool_list(localhost_network.network_address),
            localhost_network.prefixlen
        )
    )

    src_port = random.randrange(1024, 65536)
    dst_port = random.randrange(1024, 65536)

    test_message = bytes(
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=50)),
        encoding='utf8'
    )

    pkt_adr_log = []
    time_log = []

    recv_thread = threading.Thread(
        target=udp_listen,
        args=(str(dst_IP), dst_port, 1.0, pkt_adr_log, time_log)
    )
    recv_thread.start()

    time.sleep(0.5)

    udp_send(str(src_IP), src_port, str(dst_IP), dst_port,
             [test_message], [0.0])

    recv_thread.join()

    if len(pkt_adr_log) == 0:
        return 0.0

    addr = pkt_adr_log[0][1]
    if addr != (str(src_IP), src_port):
        return 0.0

    sent = test_message.decode()
    received = "".join([t.decode() for (t, _) in pkt_adr_log])
    if sent != received:
        return 0.0

    return 1.0


def transparency_test():
    tcp_score = _single_tcp_transparency()
    udp_score = _single_udp_transparency()

    score = 0.5 * (tcp_score + udp_score)

    if score < 1.0:
        print("TODO: EXPAND TRANSPARENCY TEST")

    return score
