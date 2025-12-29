# YOU CAN MODIFY THIS FILE

import csv
import ipaddress
import dpkt 

def parse_nat_config (filepath):
    data = []
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            nat_entry = {
                "NatType": row['NatType'],
                "Internal_IP": row['Internal_IP'],
                "External_IP": row['External_IP']
            }
            # Add ReservationTime if present
            if 'ReservationTime' in row and row['ReservationTime']:
                nat_entry["ReservationTime"] = row['ReservationTime']
            data.append(nat_entry)  
    return data

def parse_blacklist_config (filepath):
    data = []
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            source_port_start, source_port_end = map(int, row['Source_Port'].split('-'))
            dest_port_start, dest_port_end = map(int, row['Destination_Port'].split('-'))
            data.append({
                "Protocol": row['Protocol'],
                "Source_IP": row['Source_IP'],
                "Destination_IP": row['Destination_IP'],
                "Source_Port": (source_port_start, source_port_end),
                "Destination_Port": (dest_port_start, dest_port_end)
            })
    return data

def parse_ratelimit_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"Ratelimit": float(row['Ratelimit']), "IdleLifespan": float(row['IdleLifespan'])}
            return data
        


def parse_ttl_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"MaxTTL": int(row['MaxTTL']), "MinTTL": int(row['MinTTL'])}
            return data
        
def parse_portscan_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"SynNum": int(row['SynNum']), "MaxPacketInterval": float(row['MaxPacketInterval'])}
            return data

#blacklist helper finc
#check if an IP address is in a network
def ip_in_network(ip_str, network_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        network = ipaddress.IPv4Network(network_str, strict=False)
        return ip in network
    except:
        return False

def port_in_range(port, port_range):
    port_start, port_end = port_range
    return port_start <= port <= port_end

def protocol_matches(packet_protocol, rule_protocol):
    if rule_protocol == "IP":
        return True  
    elif rule_protocol == "UDP":
        return packet_protocol == 17  
    elif rule_protocol == "TCP":
        return packet_protocol == 6  
    return False

def check_blacklist_match(src_ip, dst_ip, src_port, dst_port, protocol, blacklist_rules):
    # Check if packet matches any blacklist rule
    for rule in blacklist_rules:
        
        if not protocol_matches(protocol, rule["Protocol"]):
            continue
            
        if not ip_in_network(src_ip, rule["Source_IP"]):
            continue
        if not ip_in_network(dst_ip, rule["Destination_IP"]):
            continue
            
        if not port_in_range(src_port, rule["Source_Port"]):
            continue
        if not port_in_range(dst_port, rule["Destination_Port"]):
            continue
            
        return True
    
    return False

#ratelimit helper
flow_buckets = {}

def get_flow_key(src_ip, src_port, dst_ip, dst_port):
  
    return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

def cleanup_expired_flows(current_time, idle_timeout):
   
    expired_flows = []
    for flow_key, flow_data in flow_buckets.items():
        if current_time - flow_data["last_packet"] > idle_timeout:
            expired_flows.append(flow_key)
    
    for flow_key in expired_flows:
        del flow_buckets[flow_key]

def check_rate_limit(src_ip, src_port, dst_ip, dst_port, packet_size, current_time, rate_limit, idle_timeout):
    
    global flow_buckets
    
    cleanup_expired_flows(current_time, idle_timeout)
    
    flow_key = get_flow_key(src_ip, src_port, dst_ip, dst_port)
    
    if flow_key not in flow_buckets:
        flow_buckets[flow_key] = {
            "bucket": 0.0,
            "last_update": current_time,
            "last_packet": current_time
        }
    
    flow_data = flow_buckets[flow_key]
    
    time_elapsed = current_time - flow_data["last_update"]
    
    leaked_bytes = time_elapsed * rate_limit
    flow_data["bucket"] = max(0.0, flow_data["bucket"] - leaked_bytes)
    
    flow_data["last_update"] = current_time
    
    if flow_data["bucket"] + packet_size > rate_limit:
        return True
    
    flow_data["bucket"] += packet_size
    flow_data["last_packet"] = current_time
    
    return False

#portscan
portscan_states = {}

def cleanup_expired_portscans(current_time, max_interval):
    
    global portscan_states
    expired_scans = []
    
    for scan_key, scan_data in portscan_states.items():
        if current_time - scan_data["last_syn_time"] > max_interval:
            expired_scans.append(scan_key)
    
    for scan_key in expired_scans:
        del portscan_states[scan_key]

def is_tcp_syn_packet(tcp_header):
    return (tcp_header.flags & 0x02) != 0 and (tcp_header.flags & 0x10) == 0

def detect_portscan(src_ip, dst_ip, tcp_header, dst_port, current_time, syn_threshold, max_interval):
    
    global portscan_states
    
    if not is_tcp_syn_packet(tcp_header):
        return False
    
    print(f"DEBUG: SYN packet from {src_ip} to {dst_ip}:{dst_port}")
    
    cleanup_expired_portscans(current_time, max_interval)
    
    scan_key = (src_ip, dst_ip)
    
    if scan_key not in portscan_states:
        portscan_states[scan_key] = {
            "ports": set(),
            "last_syn_time": current_time,
            "in_scan": False
        }
    
    scan_data = portscan_states[scan_key]
    
    time_since_last = current_time - scan_data["last_syn_time"]
    
    if time_since_last > max_interval:
        scan_data["ports"] = set()
        scan_data["in_scan"] = False
    
    scan_data["last_syn_time"] = current_time
    
    scan_data["ports"].add(dst_port)
    
    if len(scan_data["ports"]) > syn_threshold:
        scan_data["in_scan"] = True
        return True
    
    return False

# NAT functions  
def apply_quarter_nat(ip_packet, nat_configs):
    
    if ip_packet.p != dpkt.ip.IP_PROTO_UDP:
        return False
    
    src_ip = str(ipaddress.IPv4Address(ip_packet.src))
    
    quarter_nat_rule = None
    for nat_rule in nat_configs:
        if nat_rule["NatType"] == "Quarter":
            if ip_in_network(src_ip, nat_rule["Internal_IP"]):
                quarter_nat_rule = nat_rule
                break
    
    if quarter_nat_rule is None:
        return False
    
    external_ip = ipaddress.IPv4Address(quarter_nat_rule["External_IP"])
    ip_packet.src = int(external_ip)
    
    ip_packet.sum = 0
    if hasattr(ip_packet.data, 'sum'):
        ip_packet.data.sum = 0
    
    return True


# halfnat functions
halfnat_port_mappings = {}  
halfnat_used_ports = {}     

def cleanup_expired_halfnat_mappings(current_time, reservation_time):
    global halfnat_port_mappings, halfnat_used_ports
    
    expired_mappings = []
    for mapping_key, (external_port, timestamp) in halfnat_port_mappings.items():
        if current_time - timestamp > reservation_time:
            expired_mappings.append(mapping_key)
    
    for mapping_key in expired_mappings:
        if mapping_key in halfnat_port_mappings:
            external_port, _ = halfnat_port_mappings[mapping_key]
            del halfnat_port_mappings[mapping_key]
            
            for external_ip, port_dict in halfnat_used_ports.items():
                if external_port in port_dict:
                    if current_time - port_dict[external_port] > reservation_time:
                        del port_dict[external_port]

def find_available_external_port(external_ip, preferred_port, current_time, reservation_time):
    global halfnat_used_ports
    
    
    if external_ip not in halfnat_used_ports:
        halfnat_used_ports[external_ip] = {}
    
    used_ports = halfnat_used_ports[external_ip]
    
    expired_ports = []
    for port, timestamp in used_ports.items():
        if current_time - timestamp > reservation_time:
            expired_ports.append(port)
    
    for port in expired_ports:
        del used_ports[port]
    
    if preferred_port not in used_ports:
        return preferred_port
    
    for port_offset in range(1, 1000): 
        candidate_port = preferred_port + port_offset
        if candidate_port > 65535:
            candidate_port = candidate_port - 65536 + 1024 
        
        if candidate_port not in used_ports and candidate_port >= 1024:
            return candidate_port
    
    
    return preferred_port

def apply_half_nat(ip_packet, nat_configs, current_time):
    
    global halfnat_port_mappings, halfnat_used_ports
    
    if ip_packet.p != dpkt.ip.IP_PROTO_UDP:
        return False
    
    src_ip = str(ipaddress.IPv4Address(ip_packet.src))
    
    half_nat_rule = None
    reservation_time = 2.0  
    
    for nat_rule in nat_configs:
        if nat_rule["NatType"] == "Half":
            if ip_in_network(src_ip, nat_rule["Internal_IP"]):
                half_nat_rule = nat_rule
                if "ReservationTime" in nat_rule:
                    reservation_time = float(nat_rule["ReservationTime"])
                break
    
    if half_nat_rule is None:
        return False
    
    
    cleanup_expired_halfnat_mappings(current_time, reservation_time)
    
    udp_header = ip_packet.data
    internal_port = udp_header.sport
    external_ip_str = half_nat_rule["External_IP"]
    external_ip = ipaddress.IPv4Address(external_ip_str)
    
    mapping_key = (src_ip, internal_port)
    
    if mapping_key in halfnat_port_mappings:
        external_port, _ = halfnat_port_mappings[mapping_key]
        halfnat_port_mappings[mapping_key] = (external_port, current_time)
        
        if external_ip_str not in halfnat_used_ports:
            halfnat_used_ports[external_ip_str] = {}
        halfnat_used_ports[external_ip_str][external_port] = current_time
    else:
        external_port = find_available_external_port(external_ip_str, internal_port, current_time, reservation_time)
        
        halfnat_port_mappings[mapping_key] = (external_port, current_time)
        halfnat_used_ports[external_ip_str][external_port] = current_time
    
    ip_packet.src = int(external_ip)
    udp_header.sport = external_port
    
    ip_packet.sum = 0
    udp_header.sum = 0
    
    return True