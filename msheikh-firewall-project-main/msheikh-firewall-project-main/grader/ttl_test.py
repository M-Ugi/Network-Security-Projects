import ipaddress
import random
import threading
import time
import socket
from grader_utility import *


def _send_udp_with_ttl(src_ip, src_port, dst_ip, dst_port, ttl, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    s.bind((src_ip, src_port))
    s.settimeout(0.5)
    try:
        s.sendto(payload, (dst_ip, dst_port))
    except Exception as e:
        pass
    finally:
        s.close()


def ttl_test():
    ttl_config = parse_ttl_config("configuration_files/ttl_config.csv")
    ttl_min = ttl_config["MinTTL"]  
    ttl_max = ttl_config["MaxTTL"]  

    
    src_IP = "127.0.0.1"
    dst_IP = "127.0.0.2"

    src_port = random.randrange(1024, 65536)
    dst_port = random.randrange(1024, 65536)

    pkt_adr_log = []
    time_log = []

    recv_thread = threading.Thread(
        target=udp_listen,
        args=(dst_IP, dst_port, 2.0, pkt_adr_log, time_log)
    )
    recv_thread.start()
    time.sleep(0.3)

    _send_udp_with_ttl(src_IP, src_port, dst_IP, dst_port, 
                       ttl_min - 1, b"LOW_TTL")

    time.sleep(0.2)
 
    _send_udp_with_ttl(src_IP, src_port + 1, dst_IP, dst_port,
                       ttl_max + 1, b"HIGH_TTL")

    time.sleep(0.2)

    _send_udp_with_ttl(src_IP, src_port + 2, dst_IP, dst_port,
                       64, b"VALID_TTL")  

    time.sleep(0.2)

    recv_thread.join()

    if len(pkt_adr_log) == 0:
        print("TTL TEST: no packets received at all")
        return 0.0

    received_payloads = [pkt for (pkt, addr) in pkt_adr_log]
    received_data = b"".join(received_payloads)

    print(f"TTL TEST: received {len(pkt_adr_log)} packets")
    print(f"TTL TEST: received data: {received_data}")

    if b"VALID_TTL" not in received_data:
        print("TTL TEST: valid TTL packet did not arrive")
        return 0.0

    if b"LOW_TTL" in received_data:
        print("TTL TEST: low TTL packet was not filtered")
        return 0.0

    if b"HIGH_TTL" in received_data:
        print("TTL TEST: high TTL packet was not filtered")
        return 0.0

    print("TTL TEST: passed - only valid TTL packet received")
    return 1.0