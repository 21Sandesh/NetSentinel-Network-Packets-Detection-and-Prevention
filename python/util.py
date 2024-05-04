import pyshark
import datetime
from collections import defaultdict
import time
import joblib
import numpy as np
import pandas as pd

def format_timestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d - %H:%M:%S')

def decode_flags(hex_flags):
    # Dictionary mapping hexadecimal flags to their corresponding flag names
    flag_mapping = {
        '0x0018': 'SF',
        '0x0010': 'S0',
        '0x0002': 'REJ',
        '0x0004': 'RSTO',
        '0x0005': 'RSTR',
    }
    return flag_mapping.get(hex_flags, 0)

def calculate_duration(prev_time, current_time):
    if prev_time is not None:
        duration = current_time - prev_time
        return duration
    return None

def get_protocol(protocol_data):
    top_protocol = protocol_data.split(':')
    return top_protocol[3]

def get_source_port(pkt):
    try:
        src_port = pkt.tcp.srcport if 'tcp' in pkt else (pkt.udp.srcport if 'udp' in pkt else 0)
        return src_port
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def get_flag(pkt):
    try:
        tcp_flags = pkt.tcp.flags
        decoded_flag = decode_flags(tcp_flags)
        return decoded_flag
    except Exception as e:
        # print(f"Error processing packet: {e}")
        return 0

def get_bytes(pkt):
    try:
        src_bytes = int(pkt.length)
        dst_bytes = int(pkt.length)
        return src_bytes, dst_bytes
    except Exception as e:
        # print(f"Error processing packet: {e}")
        return 0, 0

def calculate_count(src_ip, count_dict):
    try:
        current_timestamp = time.time()

        if src_ip in count_dict:
            if current_timestamp - count_dict[src_ip]['timestamp'] <= 2:
                count_dict[src_ip]['count'] += 1
            else:
                count_dict[src_ip]['timestamp'] = current_timestamp
                count_dict[src_ip]['count'] = 1
        else:
            count_dict[src_ip]['timestamp'] = current_timestamp
            count_dict[src_ip]['count'] = 1

        return count_dict[src_ip]['count']
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None
    
def serror_rate(pkt, src_ip, dst_ip, protocol, flags):
    try:
        total_packets = 0
        syn_error_packets = 0

        # Increment total packets counter
        total_packets += 1

        syn_flag = 'SYN' in flags
        error_condition_indicators = pkt.tcp.flags_res  # Assuming these indicate error conditions
        connection_status = 'ACK' in flags  # Assuming ACK flag indicates successful connection
        packet_length = int(pkt.length)
        timestamp = pkt.sniff_time

        # Check if the packet represents a connection establishment phase and has a SYN error
        syn_error = protocol == 'TCP' and syn_flag and not connection_status

        # Increment syn error packets counter if a SYN error is found
        if syn_error:
            syn_error_packets += 1

        # Print packet information and error status
        # print(f"Packet {total_packets}:")
        # print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Flags: {flags}")
        # print(f"Error Condition Indicators: {error_condition_indicators}, Connection Status: {connection_status}")
        # print(f"Packet Length: {packet_length}, Timestamp: {timestamp}")
        # print(f"Error: {'SYN Error' if syn_error else 'No Error'}")  # Display error status
        # print()

        # Calculate serror_rate
        serror_rate = (syn_error_packets / total_packets) * 100 if total_packets > 0 else 0

        return serror_rate
    except Exception as e:
        # print(f"Error processing packet: {e}")
        return 0

def srv_serror_rate(pkt, src_ip, dst_ip, protocol, flag):
    try:
        srv_error_count = defaultdict(lambda: {'total_connections': 0, 'error_connections': 0})
        src_port = pkt[pkt.transport_layer].srcport
        dst_port = pkt[pkt.transport_layer].dstport
        service = get_source_port(pkt)
        
        srv_error_count[service]['total_connections'] += 1
        
        # Check if flag indicates a SYN error
        if protocol == 'tcp' and flag in ['S0', 'REJ', 'RSTO', 'RSTR']:  # Assuming these flags indicate SYN errors
            srv_error_count[service]['error_connections'] += 1
            
        for service, info in srv_error_count.items():
            total_connections = info['total_connections']
            error_connections = info['error_connections']
            srv_serror_rate = (error_connections / total_connections) * 100 if total_connections != 0 else 0
            # print(f"Service: {service}, Srv_serror_rate: {srv_serror_rate}%")
            return srv_serror_rate
    except Exception as e:
        # print(f"Error processing packet: {e}")
        return 0

def calculate_rerror_rate(pkt, rerror_rate_dict):
    try:
        protocol = pkt.transport_layer
        flag = pkt.tcp.flags if protocol == 'TCP' else None  # Adjust for other protocols if needed

        # Increment the total number of connections
        total_connections = rerror_rate_dict['total_connections']
        total_connections += 1
        rerror_rate_dict['total_connections'] = total_connections

        # Check if the flag indicates a "REJ" error
        if flag and 'REJ' in flag:
            # Increment the number of connections with "REJ" errors
            rej_errors = rerror_rate_dict['rej_errors']
            rej_errors += 1
            rerror_rate_dict['rej_errors'] = rej_errors

        # Calculate Rerror_rate
        rerror_rate = (rerror_rate_dict['rej_errors'] / rerror_rate_dict['total_connections']) * 100 if rerror_rate_dict['total_connections'] != 0 else 0
        return rerror_rate
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0

def calculate_srv_rerror_rate(pkt, srv_rerror_rate_dict):
    try:
        protocol = pkt.transport_layer
        flag = pkt.tcp.flags if protocol == 'TCP' else None  # Adjust for other protocols if needed

        # Increment the total number of connections
        total_connections = srv_rerror_rate_dict['total_connections']
        total_connections += 1
        srv_rerror_rate_dict['total_connections'] = total_connections

        # Check if the flag indicates a "REJ" error
        if flag and 'REJ' in flag:
            # Increment the number of connections with "REJ" errors
            rej_errors = srv_rerror_rate_dict['rej_errors']
            rej_errors += 1
            srv_rerror_rate_dict['rej_errors'] = rej_errors

        # Calculate Srv_rerror_rate
        srv_rerror_rate = (srv_rerror_rate_dict['rej_errors'] / srv_rerror_rate_dict['total_connections']) * 100 if srv_rerror_rate_dict['total_connections'] != 0 else 0
        return srv_rerror_rate
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0

def calculate_same_srv_rate(pkt, srv_count, total_connections):
    try:
        # Extract the destination port from the packet
        dst_port = pkt[pkt.transport_layer].dstport

        # Increment the counter for the destination port (service)
        srv_count[dst_port] += 1

        # Calculate Same_srv_rate for the current service
        current_srv_count = srv_count[dst_port]
        same_srv_rate = (current_srv_count / total_connections) * 100

        return same_srv_rate

    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0

def calculate_srv_diff_host_rate(srv_host_count, srv_count, dst_port, src_ip):
    try:
        # Increment the counter for the destination port (service)
        srv_count[dst_port] += 1
        
        # Increment the counter for the destination port and source IP (service and host)
        srv_host_count[dst_port].add(src_ip)

        # Calculate srv_diff_host_rate for the current service
        diff_host_count = len(srv_host_count[dst_port])
        total_connections = srv_count[dst_port]
        diff_host_rate = ((total_connections - diff_host_count) / total_connections) * 100 if total_connections != 0 else 0
        
        # Yield the calculated srv_diff_host_rate for the current service
        return  diff_host_rate
        
    except Exception as e:
        print(f"Error processing packet: {e}")

def calculate_dst_host_count(dst_ip, dst_host_count):
    try:
        # Increment the counter for the destination host
        dst_host_count[dst_ip] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    return dst_host_count

def calculate_dst_host_srv_count(dst_ip, dst_port, dst_host_srv_count):
    try:
        # Create a unique key for the combination of destination IP address and destination port
        key = (dst_ip, dst_port)

        # Increment the counter for the destination host's service
        dst_host_srv_count[key] += 1

        # Return the count of connections to the destination host's service
        return dst_host_srv_count[key]

    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def calculate_dst_host_same_srv_rate(dst_ip, dst_port, dst_host_srv_count):
    try:
        # Create a unique key for the combination of destination IP address and destination port
        key = (dst_ip, dst_port)

        # Get the count of connections to the same service on the destination host
        count_same_srv = dst_host_srv_count.get(key, 0)

        # Calculate the total number of connections to the destination host
        total_connections = sum(dst_host_srv_count.values())

        # Calculate dst_host_same_srv_rate
        dst_host_same_srv_rate = (count_same_srv / total_connections) * 100 if total_connections != 0 else 0

        return dst_host_same_srv_rate

    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def calculate_dst_host_diff_srv_rate(dst_ip, dst_port, dst_host_srv_count, total_connections):
    try:
        # Calculate the total number of connections to the destination host's services
        total_srv_connections = sum(dst_host_srv_count.values())

        # Calculate the number of connections to different services on the destination host
        diff_srv_connections = total_srv_connections - dst_host_srv_count.get((dst_ip, dst_port), 0)

        # Calculate dst_host_diff_srv_rate
        dst_host_diff_srv_rate = (diff_srv_connections / total_connections) * 100 if total_connections != 0 else 0

        return dst_host_diff_srv_rate

    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def calculate_dst_host_same_src_port_rate(src_ip, src_port, dst_ip, dst_host_src_port_count):
    try:
        # Create a unique key for identifying the destination host's source port
        key = (dst_ip, src_port)

        # Increment the counter for the combination of destination IP address and source port
        dst_host_src_port_count[key] += 1

        # Calculate the total number of connections to the destination host
        total_connections = sum(dst_host_src_port_count.values())

        # Calculate the number of connections to the same source port for the destination host
        same_src_port_connections = dst_host_src_port_count[key]

        # Calculate the dst_host_same_src_port_rate
        dst_host_same_src_port_rate = (same_src_port_connections / total_connections) * 100 if total_connections != 0 else 0

        return dst_host_same_src_port_rate

    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0

def calculate_dst_host_srv_diff_host_rate(dst_ip, dst_port, src_ip, dst_host_srv_count, dst_host_srv_diff_host_count):
    try:
        # Create a unique key for identifying the destination host's service
        key = (dst_ip, dst_port)

        # Increment the counter for the destination host's service
        dst_host_srv_count[key] += 1

        # Increment the counter for the combination of destination host's service and source IP address
        dst_host_srv_diff_host_count[key].add(src_ip)

        # Calculate the total number of connections to the destination host's service
        total_connections = dst_host_srv_count[key]

        # Calculate the number of connections to different hosts among the connections to the same service
        diff_host_connections = len(dst_host_srv_diff_host_count[key])

        # Calculate the dst_host_srv_diff_host_rate
        dst_host_srv_diff_host_rate = (diff_host_connections / total_connections) * 100 if total_connections != 0 else 0

        return dst_host_srv_diff_host_rate

    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0
    
def PredictAttack(new_data_str):
    # Load the preprocessor model
    preprocessor = joblib.load('./python/models/preprocessor.pkl')

    # Load Trained Model
    loaded_model = joblib.load('./python/models/best_model.pkl')

    # Parse the string data into a list
    new_data_list = [int(x) if x.isdigit() else x for x in new_data_str.strip('()').split(',')]
    
    # Convert the list to a DataFrame with column names
    new_data_df = pd.DataFrame([new_data_list], columns=[
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate'
    ])
    
    # Preprocess the new data using the loaded preprocessor model
    processed_new_data = preprocessor.transform(new_data_df)
    
    # Convert the processed data to a string without brackets and spaces
    processed_new_data_str = ','.join(map(str, processed_new_data[0]))
    
    input_data = np.array([float(x) for x in processed_new_data_str.split(',')]).reshape(1, -1)
    
    # Make Predictions
    return loaded_model.predict(input_data)[0]