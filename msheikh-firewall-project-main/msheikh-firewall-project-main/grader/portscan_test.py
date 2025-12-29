import random
import time
import threading
from grader_utility import *

def portscan_test():
    
    
    src_ip = "127.8.8.1"
    dst_ip = "127.8.8.2"
    base_port = 9000
    
    ports_to_test = 120
    expected_allowed = 100
    
    listeners = []
    received_connections = []
    
    for i in range(ports_to_test):
        port = base_port + i
        pkt_log = []
        time_log = []
        
        listener_thread = threading.Thread(
            target=tcp_listen, 
            args=(dst_ip, port, 0.5, pkt_log, time_log)
        )
        listener_thread.start()
        listeners.append((listener_thread, pkt_log))
    
    time.sleep(0.2)  
    
    print(f"PORTSCAN TEST: Started {ports_to_test} listeners")
    
    src_port_base = random.randrange(20000, 40000)
    
    for i in range(ports_to_test):
        try:
            src_port = src_port_base + i
            dst_port = base_port + i
            
            tcp_send(src_ip, src_port, dst_ip, dst_port, [b"SCAN"], [0.0])
            
            time.sleep(0.01)
            
        except Exception as e:
            pass
    
    print(f"PORTSCAN TEST: Sent connection attempts to {ports_to_test} ports")
    
    time.sleep(1.0)
    
    successful_connections = 0
    for listener_thread, pkt_log in listeners:
        if len(pkt_log) > 0:
            successful_connections += 1
    
    print(f"PORTSCAN TEST: {successful_connections} out of {ports_to_test} connections succeeded")
    
    if successful_connections <= expected_allowed:
        score = 1.0
        print("PORTSCAN TEST: Portscan detection working correctly ")
    else:
        excess = successful_connections - expected_allowed
        total_excess = ports_to_test - expected_allowed
        score = max(0.0, 1.0 - (excess / total_excess))
        print(f"PORTSCAN TEST: {excess} excess connections, score: {score}")
    
    return score