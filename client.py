import socket
import random
import sys
import pickle
import time
# Client Setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_ip = sys.argv[1]
server_port = int(sys.argv[2])
print(f"Server's IP address : {server_ip}")
print(f"Server's port : {server_port}")
server_address = (server_ip, server_port)
INITIAL_SEQ_NUM = random.randint(1, 10000)
INITIAL_ACK_NUM = 0
server_seq_num = 0
server_ack_num = 0

# TCP Segment Structure

class TCPSegment:
    def __init__(self, pkt_type, data, seq_num, ack_num):
        self.pkt_type = pkt_type
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num
    
    def create_segment(self):
        return {
            'seq_num': self.seq_num,
            'ack_num': self.ack_num,
            'data': self.data,
            'pkt_type': self.pkt_type
        }

def send_pkt(seg):
    client_socket.sendto(pickle.dumps(seg), server_address)
    print(f"\tSend packet : {seg.pkt_type} : SEQ = {seg.seq_num} : ACK = {seg.ack_num}")
    
def recv_pkt():
    response, _ = client_socket.recvfrom(1024)
    response = pickle.loads(response)
    INITIAL_SEQ_NUM = response.ack_num
    INITIAL_ACK_NUM = response.seq_num+len(str(response.data))+1
    print(f"\tReceive packet : {response.pkt_type} : SEQ = {response.seq_num} : ACK = {response.ack_num}")
    return response
    
def request_file(num):
    filename = input("Input file name : ")
    print(f"(task{num} : {filename})")
    global INITIAL_SEQ_NUM,INITIAL_ACK_NUM
    segment = TCPSegment(pkt_type="PSH", data=filename, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    response, _ = client_socket.recvfrom(1024)
    response = pickle.loads(response)
    file_size = response.data
    received_size = 0
    file_data = bytearray()
    while received_size < file_size:
        if (file_size-received_size) >= 1024:
            response, _ = client_socket.recvfrom(1024)
            response = pickle.loads(response)    
            INITIAL_SEQ_NUM = response.ack_num
            INITIAL_ACK_NUM = response.seq_num+len(str(response.data))+1
            print(f"\tReceive packet : {response.pkt_type} : SEQ = {response.seq_num} : ACK = {response.ack_num}")
            chunk = response.data
            received_size+=len(chunk)
            file_data.extend(chunk)
            #time.sleep(0.1)
            segment = TCPSegment(pkt_type="ACK", data=filename, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
            send_pkt(segment)
        else:
            response, _ = client_socket.recvfrom(file_size-received_size+150)
            response = pickle.loads(response)
            INITIAL_SEQ_NUM = response.ack_num
            INITIAL_ACK_NUM = response.seq_num+len(str(response.data))+1
            print(f"\tReceive packet : {response.pkt_type} : SEQ = {response.seq_num} : ACK = {response.ack_num}")
            chunk = response.data
            received_size+=len(chunk)
            file_data.extend(chunk)
            #time.sleep(0.1)
            segment = TCPSegment(pkt_type="ACK", data=filename, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
            send_pkt(segment)
    with open('received_'+filename, 'wb') as f:
        f.write(file_data)
    if filename.endswith(".txt"):
        print("Result : ", file_data.decode())
    print(f"(task{num} end)")
    return

def request_dns(num):
    domain_name = input("Input domain name : ")
    print(f"(task{num} : {domain_name})")
    global INITIAL_SEQ_NUM
    global INITIAL_ACK_NUM
    segment = TCPSegment(pkt_type="PSH", data=domain_name, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    response = recv_pkt()
    time.sleep(0.1)
    segment = TCPSegment(pkt_type="ACK", data="", seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    print(f"DNS result for {domain_name}: {response.data}")
    print(f"(task{num} end)")
    return


def request_calculation(num):
    operations = input("Input operations : ")
    print(f"(task{num} : {operations})")
    segment = TCPSegment(pkt_type="PSH", data=operations, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    time.sleep(0.1)
    response = recv_pkt()
    segment = TCPSegment(pkt_type="ACK", data=operations, seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    print(f"Calculation result: {response.data}")
    print(f"(task{num} end)")
    return

print("(Connecting...)")
# 3-Way Handshake
# 1. Send SYN
segment = TCPSegment(pkt_type="SYN", data="", seq_num=INITIAL_SEQ_NUM, ack_num=0)
send_pkt(segment)
# 2. Receive SYN-ACK
syn_ack, _ = client_socket.recvfrom(1024)
syn_ack = pickle.loads(syn_ack)
if syn_ack.pkt_type == 'SYN-ACK':
    server_seq_num = syn_ack.seq_num
    server_ack_num = syn_ack.ack_num
    INITIAL_SEQ_NUM = server_ack_num
    INITIAL_ACK_NUM = server_seq_num + 1
    print(f"\tReceived packet : {syn_ack.pkt_type} : SEQ = {server_seq_num} , ACK = {server_ack_num}")
    # 3. Send ACK
    time.sleep(0.1)
    segment = TCPSegment(pkt_type="ACK", data="", seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
    send_pkt(segment)
    print("(Connected)")
    
# Example Requests    
num = input("How many tasks : ")
for i in range(int(num)):
    task = input(f"Input your {i+1} task (DNS or CAL or FILE): ")
    print("(Requested tasks)")
    if task == "DNS":request_dns(i+1)
    elif task == "CAL":request_calculation(i+1)
    else:request_file(i+1)
print("(Out of tasks)")
print("(Disconnecting...)")
time.sleep(1)
segment = TCPSegment(pkt_type="FIN", data="", seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
send_pkt(segment)
fin_ack, _ = client_socket.recvfrom(1024)
fin_ack = pickle.loads(fin_ack)
server_seq_num = fin_ack.seq_num
server_ack_num = fin_ack.ack_num
INITIAL_SEQ_NUM = server_ack_num
INITIAL_ACK_NUM = server_seq_num + 1
print(f"\tReceived packet : {fin_ack.pkt_type} : SEQ = {server_seq_num} , ACK = {server_ack_num}")
time.sleep(0.1)
segment = TCPSegment(pkt_type="ACK", data="", seq_num=INITIAL_SEQ_NUM, ack_num=INITIAL_ACK_NUM)
send_pkt(segment)
print("(Disconnected)")
client_socket.close()

