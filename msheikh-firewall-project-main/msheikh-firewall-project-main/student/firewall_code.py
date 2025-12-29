import dpkt
import time
import ipaddress
import math
from firewall_utility import *

# DO NOT MODIFY SIGNATURE
def firewall_init ():

    # TODO: Perform any intitialization for your firewall here

    global blacklist_config
    global nat_config
    global ratelimit_config
    global portscan_config
    global syn_threshold    
    global max_packet_interval 

    blacklist_path = "configuration_files/blacklist_config.csv"
    blacklist_config = parse_blacklist_config(blacklist_path)
    nat_path = "configuration_files/nat_config.csv"
    nat_config = parse_nat_config(nat_path)
    ratelimit_path = "configuration_files/ratelimit_config.csv"
    ratelimit_config = parse_ratelimit_config(ratelimit_path)
    ttl_path = "configuration_files/ttl_config.csv"
    ttl_config = parse_ttl_config(ttl_path)
    portscan_path = "configuration_files/portscan_config.csv"
    portscan_config = parse_portscan_config(portscan_path)

    global ratelimit_R
    global idlelifespan
    ratelimit_R = ratelimit_config["Ratelimit"]
    idlelifespan = ratelimit_config["IdleLifespan"]

    global ttl_min
    global ttl_max
    ttl_min = ttl_config["MinTTL"]
    ttl_max = ttl_config["MaxTTL"]

    syn_threshold = portscan_config["SynNum"]
    max_packet_interval = portscan_config["MaxPacketInterval"]

    # TODO: Select the tasks you want to be graded for here
    task_selection = dict()
    task_selection["ipnull"] = True
    task_selection["ttl"] = True
    task_selection["blacklist"] = True
    task_selection["quarternat"] = True
    task_selection["halfnat"] = True
    task_selection["fullnat"] = False
    task_selection["ratelimit"] = True
    task_selection["ddos"] = False
    task_selection["portscan"] = True

    return task_selection

# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max
    global blacklist_config
    global max_packet_interval
    global syn_threshold
    global nat_config

    ip = dpkt.ip.IP(pkt.get_payload())
    ts = pkt.get_timestamp()

    should_drop = False
    drop_reason = None

    # ipnull/empty packer implemntatiuon
    ip_payload_len = ip.len - (ip.hl * 4) 
    
    if ip_payload_len == 0:
        should_drop = True
        drop_reason = "ipnull"
    
    #ttl filter
    if ip.ttl < ttl_min or ip.ttl > ttl_max:
        should_drop = True
        drop_reason = "ttl"
    
    # blacklist filter             
    src_ip = str(ipaddress.IPv4Address(ip.src))
    dst_ip = str(ipaddress.IPv4Address(ip.dst))
    
    # default ports for non-UDP/TCP traffic
    src_port = 0
    dst_port = 0
    tcp_header = None
    
    # ports for UDP/TCP
    if ip.p == dpkt.ip.IP_PROTO_UDP:  
        udp = ip.data
        src_port = udp.sport
        dst_port = udp.dport
    elif ip.p == dpkt.ip.IP_PROTO_TCP:  
        tcp_header = ip.data
        src_port = tcp_header.sport
        dst_port = tcp_header.dport
    
    # check if packet matches blacklist
    if check_blacklist_match(src_ip, dst_ip, src_port, dst_port, ip.p, blacklist_config):
       should_drop = True
       drop_reason = "blacklist"

    # ratelimiter
    if check_rate_limit(src_ip, src_port, dst_ip, dst_port, ip_payload_len, ts, ratelimit_R, idlelifespan):
        should_drop = True
        drop_reason = "ratelimit"

    # portscan
    if ip.p == dpkt.ip.IP_PROTO_TCP and tcp_header is not None:
        if detect_portscan(src_ip, dst_ip, tcp_header, dst_port, ts, syn_threshold, max_packet_interval):
            should_drop = True
            drop_reason = "portscan"

    # apply NAT translation before accepting packet
    packet_modified = False
    if not should_drop:
        #quarternat
        packet_modified = apply_quarter_nat(ip, nat_config)
        #halfnat
        if not packet_modified:
            packet_modified = apply_half_nat(ip, nat_config, ts)


    # transparency, accepting all other packets that don't match a drop rule
    if should_drop:
        pkt.drop()
        return
    else:
        pkt.accept()
        return