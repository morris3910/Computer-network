import socket
import threading
import random
import hashlib
import sys
import re
import math
import os
import time
import pickle

# Initial Parameters
RTT = 30
MSS = 1024
BUFFER_SIZE = 524288
CWND = list()
RWND = 5244288
THRESHOLD = 65536
SEQ_NUM = list()
ACK_NUM = list()
pkt_num = list()
cwnd_recv = list()
cwnd_send = list()
id_lock = threading.Lock()
lock = threading.Lock()
thread_list = list()
ID_list = list()
ID_list_list = list()
recv_flag = list()
recv_list = list()
recv_pkt_list = list()
handshake = list()

# TCP Segment Structure
class TCPSegment:
    def __init__(self, pkt_type, data, seq_num, ack_num):
        self.pkt_type = pkt_type
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num

# DNS Function
def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "DNS lookup failed"

def replace(expression):
    return re.sub(r'sqrt', r'math.sqrt', expression)

def send_pkt(client_socket, client_address, pkt_type, data, seq_num, ack_num):
    seg = TCPSegment(pkt_type=pkt_type, data=data, seq_num=seq_num, ack_num=ack_num)
    client_socket.sendto(pickle.dumps(seg), client_address)
    #print(len(pickle.dumps(seg)))
    return

# File Transmission
def send_file(filename, client_socket, client_address, request, ID):
    ID = ID_list_list[ID]
    filepath = 'files/'+ filename
    file_size = os.path.getsize(filepath)
    sent_size = 0
    global SEQ_NUM,ACK_NUM, CWND, cwnd_send, cwnd_recv, MSS
    send_pkt(client_socket, client_address, " ", file_size, SEQ_NUM[ID], ACK_NUM[ID])
    SEQ_NUM[ID] = request.ack_num
    ACK_NUM[ID] = request.seq_num + len(request.data) + 1
    with open(filepath, 'rb') as f:
        while sent_size < file_size:
            #print(sent_size)
            time.sleep(0.1)
            for i in range(int(CWND[ID]/MSS-cwnd_send[ID]+cwnd_recv[ID])):
                if (file_size-sent_size) >= 900:
                    chunk = f.read(900)
                    sent_size += len(chunk)
                    if not chunk:
                        break
                    send_pkt(client_socket, client_address, "ACK", chunk, SEQ_NUM[ID], ACK_NUM[ID])
                    cwnd_send[ID]+=1
                    print(f"Send packet ({ID+1}) : SEQ = {SEQ_NUM[ID]}, ACK = {ACK_NUM[ID]}")
                else:
                    chunk = f.read(file_size-sent_size)
                    sent_size += (file_size-sent_size)
                    if not chunk:
                        break
                    send_pkt(client_socket, client_address, "ACK", chunk, SEQ_NUM[ID], ACK_NUM[ID])
                    cwnd_send[ID]+=1
                    print(f"Send packet ({ID+1}) : SEQ = {SEQ_NUM[ID]}, ACK = {ACK_NUM[ID]}")
                    break
                SEQ_NUM[ID]+=1024
            while recv_flag[ID] == 0:
                if recv_flag[ID] == 1: break     
            while len(recv_list[ID]) == 0:
                if len(recv_list[ID]) > 0 : break
            ack = recv_list[ID].pop()
            client_seq_num = ack.seq_num
            client_ack_num = ack.ack_num
            print(f"Received packet ({ID+1}) : {ack.pkt_type} : SEQ = {client_seq_num} : ACK = {client_ack_num}")
            CWND[ID]+=1024
            print(f"({ID+1}) cwnd = {CWND[ID]}, rwnd = {RWND}, threshold = {THRESHOLD}")
            SEQ_NUM[ID] = client_ack_num
            ACK_NUM[ID] = client_seq_num
            cwnd_recv[ID]+=1
        while cwnd_send[ID]-cwnd_recv[ID] > 0:
            while len(recv_list[ID]) == 0:
                if len(recv_list[ID]) > 0 : break
            ack = recv_list[ID].pop()
            client_seq_num = ack.seq_num
            client_ack_num = ack.ack_num
            print(f"Received packet ({ID+1}) : {ack.pkt_type} : SEQ = {client_seq_num} : ACK = {client_ack_num}")
            CWND[ID]+=1024
            print(f"({ID+1}) cwnd = {CWND[ID]}, rwnd = {RWND}, threshold = {THRESHOLD}")
            SEQ_NUM[ID] = client_ack_num
            ACK_NUM[ID] = client_seq_num
            cwnd_recv[ID]+=1
            return 
    return

# Client Handler
def client_handler(client_socket, client_address, ID):
    while True:
        global recv_flag,pkt_num, CWND, SEQ_NUM, ACK_NUM, handshake, cwnd_send, cwnd_recv, MSS
        if recv_flag[ID] == 0:
            continue
        if handshake[ID] == 1:
            if len(recv_list[ID]) == 0:
                continue
            request = recv_list[ID].pop()
            if request.pkt_type == 'SYN':
                client_seq_num = request.seq_num
                client_ack_num = request.ack_num
                print(f"Received packet {client_address} : {request.pkt_type} : SEQ = {client_seq_num} ACK = {client_ack_num}")
                print(f"(Add client {client_address} : ({ID+1}))")
                print(f"({ID+1}) Connecting...")
                print(f"({ID+1}) cwnd = {CWND[ID]}, rwnd = {RWND}, threshold = {THRESHOLD}")
                # 2. Send SYN-ACK
                send_pkt(client_socket, client_address, "SYN-ACK", "", SEQ_NUM[ID], client_seq_num + 1)            
                print(f"Sent packet ({ID+1}) : SYN-ACK : SEQ =  {SEQ_NUM[ID]} , ACK = {client_seq_num + 1}")
                # 3. Receive ACK
                recv_flag[ID] = 0
                handshake[ID] = 0
                while recv_flag[ID] == 0:
                    if recv_flag[ID] == 1: break     
                if recv_flag[ID] == 1:
                    while len(recv_list[ID]) == 0:
                        if len(recv_list[ID]) > 0 : break
                    ack = recv_list[ID].pop()
                    if ack.pkt_type == 'ACK':
                        client_seq_num = ack.seq_num
                        client_ack_num = ack.ack_num
                        print(f"Received packet ({ID+1}) {ack.pkt_type} : SEQ =  {client_seq_num}, ACK = {client_ack_num}")
                        print(f"({ID+1}) Connected")
                        print(f"({ID+1}) Slow start mode")
                        recv_flag[ID] = 0
                        handshake[ID] = 0
                        continue
        else:
            while recv_flag[ID] == 0:
                if recv_flag[ID] == 1: break     
            if recv_flag[ID] == 1:
                while len(recv_list[ID]) == 0:
                    if len(recv_list[ID]) > 0 : break
            request = recv_list[ID].pop()
            recv_flag[ID] = 0
            if request.pkt_type == "FIN":
                client_seq_num = request.seq_num
                client_ack_num = request.ack_num
                print(f"Received packet ({ID+1}) : {request.pkt_type} : SEQ {client_seq_num}, ACK {client_ack_num}")
                print(f"({ID+1}) Disconnecting...")
                SEQ_NUM[ID] = client_ack_num
                ACK_NUM[ID] = client_seq_num + 1
                send_pkt(client_socket, client_address, "FIN-ACK", "", SEQ_NUM[ID], ACK_NUM[ID])
                print(f"Sent packet ({ID+1}) : FIN-ACK : SEQ {SEQ_NUM[ID]}, ACK {ACK_NUM[ID]}")
                while recv_flag[ID] == 0:
                    if recv_flag[ID] == 1: break     
                if recv_flag[ID] == 1:
                    while len(recv_list[ID]) == 0:
                        if len(recv_list[ID]) > 0 : break
                    ack = recv_list[ID].pop()
                    client_seq_num = ack.seq_num
                    client_ack_num = ack.ack_num
                    print(f"Received packet ({ID+1}) : {ack.pkt_type} : SEQ = {client_seq_num} : ACK = {client_ack_num}")
                    print(f"({ID+1}) Disconnected")
                    print(f"(Del client ({ID+1}))")
                    #client_socket.close()
                    #thread_list[ID-1].join()
                    return 
            pkt_num[ID]+=1;
            if not request:
                break
            if request.pkt_type == "PSH":
                client_seq_num = request.seq_num
                client_ack_num = request.ack_num
                print(f"Received packet ({ID+1}) : {request.pkt_type} : SEQ {client_seq_num}, ACK {client_ack_num}")
                print(f"({ID+1}) try dns")
                if request.data.endswith(".com"):
                    print(f"({ID+1}) Success")
                    print(f"({ID+1}) {request.data}")    
                    domain = request.data
                    ip = dns_lookup(domain)
                    print(f"({ID+1}) DNS lookup success")
                    print(f"({ID+1}) IP: {ip}")
                    SEQ_NUM[ID] = client_ack_num
                    ACK_NUM[ID] = client_seq_num + len(domain) + 1
                    send_pkt(client_socket, client_address, "PSH-ACK", ip, SEQ_NUM[ID], ACK_NUM[ID])
                    print(f"Sent packet: PSH-ACK : SEQ {SEQ_NUM[ID]}, ACK {ACK_NUM[ID]}")
                    while recv_flag[ID] == 0:
                        if recv_flag[ID] == 1: break
                    while len(recv_list[ID]) == 0:
                        if len(recv_list[ID]) > 0 : break
                    ack = recv_list[ID].pop()
                    recv_flag[ID] = 0
                    client_seq_num = ack.seq_num
                    client_ack_num = ack.ack_num
                    print(f"Received packet ({ID+1}) : {ack.pkt_type} : SEQ = {client_seq_num} : ACK = {client_ack_num}")
                    CWND[ID]+=1024
                    print(f"({ID+1}) cwnd = {CWND[ID]}, rwnd = {RWND}, threshold = {THRESHOLD}")
                    continue
                print(f"({ID+1}) try File transmission")
                filepath = 'files/'+ request.data
                if  os.path.exists(filepath):
                    print(f"({ID+1}) Success")
                    print(f"({ID+1}) {request.data}")
                    filename = request.data
                    send_file(filename, client_socket, client_address, request, ID)
                    continue
                else:
                    print(f"({ID+1}) try Calculation")
                    print(f"({ID+1}) Success")
                    print(f"({ID+1}) {request.data}")
                    SEQ_NUM[ID] = client_ack_num
                    ACK_NUM[ID] = client_seq_num + len(request.data) + 1
                    ans = eval(replace(request.data))
                    print(f"({ID+1}) calculation success")
                    print(f"({ID+1}) result : {ans}")
                    send_pkt(client_socket, client_address, "PSH-ACK", ans, SEQ_NUM[ID], ACK_NUM[ID])
                    recv_flag[ID] = 0
                    print(f"Sent packet: PSH-ACK : SEQ {SEQ_NUM[ID]}, ACK {ACK_NUM[ID]}")
                    while recv_flag[ID] == 0:
                        if recv_flag[ID] == 1: break
                    while len(recv_list[ID]) == 0:
                        if len(recv_list[ID]) > 0 : break
                    ack = recv_list[ID].pop()
                    recv_flag[ID] = 0
                    client_seq_num = ack.seq_num
                    client_ack_num = ack.ack_num
                    print(f"Received packet ({ID+1}) : {ack.pkt_type} : SEQ = {client_seq_num} : ACK = {client_ack_num}")
                    CWND[ID]+=1024
                    print(f"({ID+1}) cwnd = {CWND[ID]}, rwnd = {RWND}, threshold = {THRESHOLD}")
                    continue
    
# Server Setup
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_port = int(sys.argv[1])
    server_socket.bind(('192.168.244.130', server_port))
    print(f"My port: {server_port}")
    ID = 0
    while True:
        global recv_flag, handshake
        id_lock.acquire()
        data, client_address = server_socket.recvfrom(1024)
        pkt = pickle.loads(data)
        if client_address not in ID_list:
            ID_list.append(client_address)
            ID_list_list.append(ID)
            recv_flag.append(1)
            handshake.append(1)
            cwnd_recv.append(0)
            cwnd_send.append(0)
            CWND.append(1024)
            SEQ_NUM.append(random.randint(1, 10000))
            ACK_NUM.append(0)
            pkt_num.append(0)
            recv_pkt_list.append(pkt)
            recv_list.append(recv_pkt_list)
            thread = threading.Thread(target=client_handler, args=(server_socket, client_address, ID))
            thread_list.append(thread)
            thread.start()
            ID += 1
            id_lock.release()
        else:
            index = ID_list.index(client_address)
            recv_list[index].append(pkt)
            recv_flag[index] = 1;
            id_lock.release()
                
if __name__ == "__main__":
    server()

