import ipaddress
import random
import threading
import time
from grader_utility import *

def blacklist_test():
    
    
    success_count = 0
    total_tests = 0
    
    # test 1 traffic that should be allowed 
    try:
        pkt_log = []
        time_log = []
        
        src_ip = "127.1.1.1"  
        dst_ip = "127.1.1.2"
        src_port = random.randrange(1024, 65535)
        dst_port = random.randrange(1024, 65535)
        
        recv_thread = threading.Thread(target=udp_listen, 
                                     args=(dst_ip, dst_port, 1.0, pkt_log, time_log))
        recv_thread.start()
        time.sleep(0.3)
        
        udp_send(src_ip, src_port, dst_ip, dst_port, [b"ALLOWED"], [0.0])
        recv_thread.join()
        
        if len(pkt_log) > 0 and b"ALLOWED" in b"".join([p for p, a in pkt_log]):
            success_count += 1
            print("BLACKLIST TEST: Allowed traffic passed ")
        else:
            print("BLACKLIST TEST: Allowed traffic was blocked ")
        total_tests += 1
    except Exception as e:
        print(f"BLACKLIST TEST: Allowed traffic test failed: {e}")
        total_tests += 1

    # traffic that shouldn't be allwoed
    try:
        pkt_log = []
        time_log = []
        
        src_ip = "127.0.0.1"    
        dst_ip = "127.0.1.1"    
        src_port = random.randrange(1024, 65535)
        dst_port = random.randrange(1024, 65535)
        
        recv_thread = threading.Thread(target=udp_listen,
                                     args=(dst_ip, dst_port, 1.0, pkt_log, time_log))
        recv_thread.start()
        time.sleep(0.3)
        
        udp_send(src_ip, src_port, dst_ip, dst_port, [b"BLOCKED_IP"], [0.0])
        recv_thread.join()
        
        if len(pkt_log) == 0 or b"BLOCKED_IP" not in b"".join([p for p, a in pkt_log]):
            success_count += 1
            print("BLACKLIST TEST: IP rule blocked traffic ")
        else:
            print("BLACKLIST TEST: IP rule failed to block traffic ")
        total_tests += 1
    except Exception as e:
        print(f"BLACKLIST TEST: IP rule test failed: {e}")
        total_tests += 1

    # test 3 udp traffic
    try:
        pkt_log = []
        time_log = []
        
        src_ip = "127.42.0.1"   
        dst_ip = "127.2.0.1"    
        src_port = random.randrange(1024, 65535)
        dst_port = 12000        
        
        recv_thread = threading.Thread(target=udp_listen,
                                     args=(dst_ip, dst_port, 1.0, pkt_log, time_log))
        recv_thread.start()
        time.sleep(0.3)
        
        udp_send(src_ip, src_port, dst_ip, dst_port, [b"BLOCKED_UDP"], [0.0])
        recv_thread.join()
        
        if len(pkt_log) == 0 or b"BLOCKED_UDP" not in b"".join([p for p, a in pkt_log]):
            success_count += 1
            print("BLACKLIST TEST: UDP rule blocked traffic ")
        else:
            print("BLACKLIST TEST: UDP rule failed to block traffic ")
        total_tests += 1
    except Exception as e:
        print(f"BLACKLIST TEST: UDP rule test failed: {e}")
        total_tests += 1

    # test 4 tcp trafffic
    try:
        pkt_log = []
        time_log = []
        
        src_ip = "127.43.0.1"   
        dst_ip = "127.3.0.1"    
        src_port = 4000        
        dst_port = 12000       
        
        recv_thread = threading.Thread(target=tcp_listen,
                                     args=(dst_ip, dst_port, 1.0, pkt_log, time_log))
        recv_thread.start()
        time.sleep(0.3)
        
        tcp_send(src_ip, src_port, dst_ip, dst_port, [b"BLOCKED_TCP"], [0.0])
        recv_thread.join()
        
        if len(pkt_log) == 0 or b"BLOCKED_TCP" not in b"".join([p for p, a in pkt_log]):
            success_count += 1
            print("BLACKLIST TEST: TCP rule blocked traffic ")
        else:
            print("BLACKLIST TEST: TCP rule failed to block traffic ")
        total_tests += 1
    except Exception as e:
        print(f"BLACKLIST TEST: TCP rule test failed: {e}")
        total_tests += 1

    if total_tests == 0:
        return 0.0
    
    score = success_count / total_tests
    print(f"BLACKLIST TEST: {success_count}/{total_tests} tests passed (score: {score})")
    return score