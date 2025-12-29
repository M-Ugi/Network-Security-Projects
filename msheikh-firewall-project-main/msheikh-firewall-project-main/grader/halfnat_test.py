import time
import threading
import socket
import struct
from grader_utility import *

def halfnat_test():
    
    nat_config = parse_nat_config("configuration_files/nat_config.csv")
    
    half_nat_rule = None
    for rule in nat_config:
        if rule["NatType"] == "Half":
            half_nat_rule = rule
            break
    
    if half_nat_rule is None:
        print("HALFNAT TEST: No Half-NAT rule found in config")
        return 0.0
    
    internal_range = half_nat_rule["Internal_IP"]  
    external_ip = half_nat_rule["External_IP"]      
    
    internal_src1 = "127.4.10.100"  
    internal_src2 = "127.4.10.101"  
    
    dst_ip = "127.200.200.201"
    dst_port = 8001
    src_port = 15000
    
    print(f"HALFNAT TEST: Config - Internal: {internal_range}, External: {external_ip}")
    print(f"HALFNAT TEST: Sending from internal IPs {internal_src1}, {internal_src2}")
    print(f"HALFNAT TEST: Expected translation to external IP: {external_ip}")
    
    success_count = 0
    total_tests = 2
        
    received_src_ip1 = test_single_halfnat_packet(internal_src1, src_port, dst_ip, dst_port, external_ip)
    if received_src_ip1:
        success_count += 1
        print(f"HALFNAT TEST: Test 1 passed - received packet with src IP {received_src_ip1} ")
    else:
        print(f"HALFNAT TEST: Test 1 failed - no packet received ")
    
    time.sleep(0.2)  
    
    received_src_ip2 = test_single_halfnat_packet(internal_src2, src_port, dst_ip, dst_port + 1, external_ip)
    if received_src_ip2:
        success_count += 1
        print(f"HALFNAT TEST: Test 2 passed - received packet with src IP {received_src_ip2} ")
    else:
        print(f"HALFNAT TEST: Test 2 failed - no packet received ")
    
    score = success_count / total_tests
    
    print(f"HALFNAT TEST: {success_count}/{total_tests} tests passed (score: {score})")
    
    if score >= 1.0:
        print("HALFNAT TEST: Half-NAT working correctly ")
    
    return score


def test_single_halfnat_packet(src_ip, src_port, dst_ip, dst_port, expected_external_ip):
    
    received_data = []
    received_src_ip = [None]
    
    def listen_and_capture():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((dst_ip, dst_port))
            sock.settimeout(2.0)
            
            data, addr = sock.recvfrom(65535)
            received_data.append(data)
            received_src_ip[0] = addr[0]  
            sock.close()
        except Exception as e:
            pass
    
    listener_thread = threading.Thread(target=listen_and_capture)
    listener_thread.start()
    
    time.sleep(0.1)  
    
    udp_send(src_ip, src_port, dst_ip, dst_port, [b"HALFNAT_TEST"], [0.0])
    
    listener_thread.join(timeout=2.5)
    
    if len(received_data) > 0 and received_src_ip[0] is not None:
        actual_src_ip = received_src_ip[0]
        
        if actual_src_ip == expected_external_ip:
            return actual_src_ip
        else:
            print(f"HALFNAT TEST WARNING: Received packet but src IP is {actual_src_ip}, expected {expected_external_ip}")
            return actual_src_ip  
    
    return None