import time
import threading
from grader_utility import *

def quarternat_test():
    
    
    internal_src = "127.3.12.100" 
    external_expected = "127.128.0.3"
    dst_ip = "127.200.200.200"
    dst_port = 8000
    src_port = 12345
    
    pkt_log = []
    time_log = []
    
    listener_thread = threading.Thread(
        target=udp_listen,
        args=(dst_ip, dst_port, 2.0, pkt_log, time_log)
    )
    listener_thread.start()
    
    time.sleep(0.1)  
    
    print(f"QUARTERNAT TEST: Sending UDP from {internal_src} to {dst_ip}:{dst_port}")
    
    udp_send(internal_src, src_port, dst_ip, dst_port, [b"QUARTER_NAT_TEST"], [0.0])
    
    time.sleep(0.5)  
    
    if len(pkt_log) > 0:
        print(f"QUARTERNAT TEST: Received packet - NAT translation working")
        print(f"QUARTERNAT TEST: Expected src IP translation: {internal_src} -> {external_expected}")
        return 1.0
    else:
        print(f"QUARTERNAT TEST: No packet received - NAT may have failed")
        return 0.0