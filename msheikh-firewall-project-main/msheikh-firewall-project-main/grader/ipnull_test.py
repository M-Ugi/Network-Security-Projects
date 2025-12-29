import ipaddress
import random
import threading
import time
import socket
import struct

from grader_utility import *


def _send_header_only_ip(src_ip_str, dst_ip_str, proto=255):
    
    src_ip = socket.inet_aton(src_ip_str)
    dst_ip = socket.inet_aton(dst_ip_str)

    version = 4
    ihl = 5  
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 20  
    identification = random.randrange(0, 65536)
    flags_fragment = 0
    ttl = 64
    protocol = proto  
    checksum = 0

    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip
    )

    packet = ip_header

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet, (dst_ip_str, 0))
    s.close()


def ipnull_test():
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

    
    pkt_adr_log = []
    time_log = []

    recv_thread = threading.Thread(
        target=tcp_listen,
        args=(str(dst_IP), dst_port, 1.0, pkt_adr_log, time_log)
    )
    recv_thread.start()

    time.sleep(0.5)

    _send_header_only_ip(str(src_IP), str(dst_IP))

    time.sleep(0.1)
    normal_payload = [b"TEST"]
    tcp_send(str(src_IP), src_port, str(dst_IP), dst_port,
             normal_payload, [0.0])

    recv_thread.join()

    if len(pkt_adr_log) == 0:
        print("IPNULL TEST: TCP packet did not arrive")
        return 0.0

    addr = pkt_adr_log[0][1]
    if addr != (str(src_IP), src_port):
        print("IPNULL TEST: source address/port mismatch")
        return 0.0

    received = b"".join([t for (t, _) in pkt_adr_log])
    if received != b"TEST":
        print("IPNULL TEST: unexpected TCP payload received")
        return 0.0

    return 1.0
