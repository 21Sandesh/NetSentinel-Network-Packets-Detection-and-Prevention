import threading
import queue
import time
from util import *
import warnings
import sys

warnings.filterwarnings('ignore')

# Define your processing function
def extract_packet_data(pkt, prev_time, count_dict, diff_srv_rates, dst_host_count, rerror_rate_dict, srv_count, srv_host_count, dst_host_srv_count, dst_host_src_port_count, dst_host_srv_diff_host_count):      
    data = ""
    src_port = ""
    try:
        current_time = int(datetime.datetime.strptime(str(pkt.sniff_time), "%Y-%m-%d %H:%M:%S.%f").timestamp())
        duration = calculate_duration(prev_time, current_time)
        protocol = get_protocol(pkt.frame_info.protocols)
        flag = get_flag(pkt)
        src_bytes, dst_bytes = get_bytes(pkt)
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt[pkt.transport_layer].srcport
        dst_port = pkt[pkt.transport_layer].dstport

        # Update connection counts for the source IP
        diff_srv_rates[src_ip]['total_connections'] += 1
        
        # Add the service to the set of unique services for the source IP
        diff_srv_rates[src_ip]['unique_services'].add(src_port)

        
        total_connections = diff_srv_rates[src_ip]['total_connections']
        unique_services = len(diff_srv_rates[src_ip]['unique_services'])


        diff_srv_rate = (unique_services / total_connections) * 100 if total_connections != 0 else 0
        rerror_rate = calculate_rerror_rate(pkt, rerror_rate_dict)
        srv_rerror_rate = calculate_srv_rerror_rate(pkt, rerror_rate_dict)

        same_srv_rates = calculate_same_srv_rate(pkt, srv_count, total_connections)
        
        data = str(duration)+","+str((protocol))+","+str((get_source_port(pkt)))+","+str((flag))+","+str((src_bytes))+","+str((dst_bytes))+","+str((calculate_count(src_ip, count_dict)))+","+str((srv_count[dst_port]))+","+str((serror_rate(pkt, src_ip, dst_ip, protocol, flag)))+","+str((srv_serror_rate(pkt, src_ip, dst_ip, protocol, flag)/100))+","+str((rerror_rate))+","+str((srv_rerror_rate))+","+str((round(same_srv_rates/100, 2)))+","+str((round(calculate_srv_diff_host_rate(srv_host_count, srv_count, dst_port, src_ip)/100, 2)))+","+str((round(diff_srv_rate/100, 2)))+","+str((dst_host_count[dst_ip]))+","+str((calculate_dst_host_srv_count(dst_ip, dst_port, dst_host_srv_count)))+","+str((round(calculate_dst_host_same_srv_rate(dst_ip, dst_port, dst_host_srv_count)/100, 2)))+","+str((round(calculate_dst_host_diff_srv_rate(dst_ip, dst_port, dst_host_srv_count, total_connections)/100, 2)))+","+str((round(calculate_dst_host_same_src_port_rate(src_ip, src_port, dst_ip, dst_host_src_port_count)/100, 2)))+","+str((round(calculate_dst_host_srv_diff_host_rate(dst_ip, dst_port, src_ip, dst_host_srv_count, dst_host_srv_diff_host_count)/100, 2)))

        prev_time = current_time
    except Exception as e:
        # print(f"Error processing packet: {e}")
        pass
    
    return data, prev_time, current_time, src_port, dst_ip

# Worker function to process packets from the queue
def packet_worker(queue):
    prev_time = 0
    while True:
        packet = queue.get()  # Get packet from the queue
        if packet is None:
            break  # If None is received, exit the loop
        data, prev_time, timestamp, src_port, dst_ip = extract_packet_data(packet, prev_time, count_dict, diff_srv_rates, dst_host_count, rerror_rate_dict, srv_count, srv_host_count, dst_host_srv_count, dst_host_src_port_count, dst_host_srv_diff_host_count)

        queue.task_done()  # Signal that the task is complete

# Function to capture live data packets and add them to the queue
def capture_and_process_live_data(queue, userIP):
    capture = pyshark.LiveCapture(interface='Wi-Fi')  # Replace 'eth0' with your network interface
    initial_packet = next(capture.sniff_continuously(packet_count=1))
    prev_time = int(datetime.datetime.strptime(str(initial_packet.sniff_time), "%Y-%m-%d %H:%M:%S.%f").timestamp())
    data = ""
    for packet in capture.sniff_continuously(packet_count=0):  # Continuous packet sniffing
        if 'ip' in packet and packet.ip.src == userIP:
            # Process the packet
            data, prev_time, time, src_port, dst_ip = extract_packet_data(packet, prev_time, count_dict, diff_srv_rates, dst_host_count, rerror_rate_dict, srv_count, srv_host_count, dst_host_srv_count, dst_host_src_port_count, dst_host_srv_diff_host_count)

            # Detect Attack
            attack = PredictAttack(data)
            timestamp = format_timestamp(time)
            returnVal = timestamp + "|" + userIP + "|" + src_port + "|" + dst_ip + "|" + attack
            print(returnVal)
            sys.stdout.flush()
            queue.put(packet)  # Add packet to the queue

# Main function
def StartCapture(userIP):

    global count_dict
    global diff_srv_rates
    global dst_host_count
    global rerror_rate_dict
    global srv_count
    global srv_host_count
    global dst_host_srv_count
    global dst_host_src_port_count
    global dst_host_srv_diff_host_count

    count_dict = defaultdict(lambda: {'timestamp': 0, 'count': 0})
    diff_srv_rates = defaultdict(lambda: {'total_connections': 0, 'unique_services': set()})
    dst_host_count = defaultdict(int)
    rerror_rate_dict = {'total_connections': 0, 'rej_errors': 0}
    srv_count = defaultdict(int)
    srv_host_count = defaultdict(set)
    dst_host_srv_count = defaultdict(int)
    dst_host_src_port_count = defaultdict(int)
    dst_host_srv_diff_host_count = defaultdict(set)

    # Create a queue for holding packets
    packet_queue = queue.Queue()

    # Create and start the packet processing worker thread
    worker_thread = threading.Thread(target=packet_worker, args=(packet_queue,))
    # print("Starting...")
    # sys.stdout.flush()
    worker_thread.start()

    # Start capturing and processing live data in the main thread
    capture_and_process_live_data(packet_queue, userIP)

    # Optionally, join the worker thread to wait for it to finish
    worker_thread.join()

if __name__ == "__main__":
    # Accept username as command line argument
    userIP = sys.argv[1]
    # print(f"Capturing packets for user: {userIP}")
    # sys.stdout.flush()
    StartCapture(userIP)