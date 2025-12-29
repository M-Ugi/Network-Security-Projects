
import random
import threading
import time
from grader_utility import *

def ratelimit_test():
    
    total_score = 0.0
    tests_run = 0
    
    try:
        udp_score = test_udp_ratelimit()
        total_score += udp_score
        tests_run += 1
        print(f"RATELIMIT TEST: UDP score: {udp_score}")
    except Exception as e:
        print(f"RATELIMIT TEST: UDP test failed: {e}")
        tests_run += 1
    
    try:
        tcp_score = test_tcp_ratelimit()
        total_score += tcp_score
        tests_run += 1
        print(f"RATELIMIT TEST: TCP score: {tcp_score}")
    except Exception as e:
        print(f"RATELIMIT TEST: TCP test failed: {e}")
        tests_run += 1
    
    if tests_run == 0:
        return 0.0
    
    final_score = total_score / tests_run
    print(f"RATELIMIT TEST: Final score: {final_score}")
    return final_score

def test_udp_ratelimit():
    src_ip = "127.6.6.1"
    dst_ip = "127.6.6.2" 
    src_port = random.randrange(1024, 65535)
    dst_port = random.randrange(1024, 65535)
    
    packet_size = 400
    packets_to_send = 8
    send_interval = 0.1  
    
    pkt_log = []
    time_log = []
    
    recv_thread = threading.Thread(target=udp_listen,
                                 args=(dst_ip, dst_port, 2.0, pkt_log, time_log))
    recv_thread.start()
    time.sleep(0.3)
    
    payloads = [b"U" * packet_size for _ in range(packets_to_send)]
    intervals = [send_interval] * packets_to_send
    
    print(f"RATELIMIT UDP: Sending {packets_to_send} packets at {packet_size/send_interval} Bps")
    udp_send(src_ip, src_port, dst_ip, dst_port, payloads, intervals)
    
    recv_thread.join()
    
    packets_received = len(pkt_log)
    print(f"RATELIMIT UDP: Sent {packets_to_send}, received {packets_received}")
    
    if packets_received < packets_to_send:
        return 1.0
    else:
        return 0.0

def test_tcp_ratelimit():
    src_ip = "127.6.6.3"
    dst_ip = "127.6.6.4"
    src_port = random.randrange(1024, 65535)
    dst_port = random.randrange(1024, 65535)
    
    packet_size = 400
    packets_to_send = 8
    send_interval = 0.1  
    
    pkt_log = []
    time_log = []
    
    recv_thread = threading.Thread(target=tcp_listen,
                                 args=(dst_ip, dst_port, 2.0, pkt_log, time_log))
    recv_thread.start()
    time.sleep(0.3)
    
    payloads = [b"T" * packet_size for _ in range(packets_to_send)]
    intervals = [send_interval] * packets_to_send
    
    print(f"RATELIMIT TCP: Sending {packets_to_send} packets at {packet_size/send_interval} Bps")
    tcp_send(src_ip, src_port, dst_ip, dst_port, payloads, intervals)
    
    recv_thread.join()
    
    packets_received = len(pkt_log)
    print(f"RATELIMIT TCP: Sent {packets_to_send}, received {packets_received}")
    
    if packets_received < packets_to_send:
        return 1.0
    else:
        return 0.0