import sys
import os
import time
import math
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle

# constants
BUF_SIZE = 1400
CHUNK_SIZE = 512 * 1024
HASH_SIZE = 20
HEADER_LEN = struct.calcsize("!HBBHHII")
MAGIC_VAL = 52305
MAX_PAYLOAD = 1024
TEAM_CODE = 28
CONNECTION_TIMEOUT = 20
REQUEST_TIMEOUT = 40

# packet types
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

from contextlib import redirect_stdout
init = True
def lprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    print(*args, **kwargs)
    global init
    if init:
        init = False
        with open(f"./log/peer-{CONFIG.identity}.log", 'w+') as f:
            with redirect_stdout(f):
                print(*args, **kwargs)
    else:
        with open(f"./log/peer-{CONFIG.identity}.log", 'a') as f:
            with redirect_stdout(f):
                print(*args, **kwargs)
    pass


class Peer:
    __sock = None

    def __init__(self, idx, hostname, port):
        self.idx, self.hostname, self.port = idx, hostname, port
        self.receive_hash = ""
        self.send_chunk = b''
        self.send_seq_list = []
        self.free = True
        self.connection_timestamp = 0

        # timeout variables
        self.timeout_interval = 114.0
        self.estimated_RTT = 0.0
        self.dev_RTT = 0.0
        self.alpha = 0.125
        self.beta = 0.25
        self.send_time_dict = {}

        # duplicate ACKs && congestion control variables
        self.ack_cnt_dict = {}
        self.cwnd = 1
        self.ssthresh = 64

    def __str__(self):
        s = f"peer[{self.idx}] at {self.hostname}:{self.port}"
        return s

    @property
    def sock(self):
        return Peer.__sock

    @sock.setter
    def sock(self, sock: simsocket.SimSocket):
        Peer.__sock = sock

    def connection_refresh(self):
        if self.receive_hash or not self.free:
            self.connection_timestamp = time.time()

    def connection_timeout(self):
        return (self.receive_hash or not self.free) \
               and self.connection_timestamp + CONNECTION_TIMEOUT < time.time()

    def connection_reset(self):
        self.connection_timestamp = 0

        if self.receive_hash:
            # verbose debug
            if 0 < CONFIG.verbose: lprint(f"{self} has stop sending chunks for {self.receive_hash}")
            DOWNLOAD.append_request(self.receive_hash)
            self.receive_hash = ""
        elif not self.free:
            self.free = True

            self.timeout_interval = 114.0
            self.estimated_RTT = 0.0
            self.dev_RTT = 0.0
            self.alpha = 0.125
            self.beta = 0.25
            self.send_time_dict = {}

            self.ack_cnt_dict = {}
            self.cwnd = 1
            self.ssthresh = 64
            # verbose debug
            if 0 < CONFIG.verbose: lprint(f"No need to send to disconnected {self}")

    def send(self, type_code: int, seq: int = 0, ack: int = 0, data: bytes = None):
        header = struct.pack("!HBBHHII",
                             MAGIC_VAL,
                             TEAM_CODE,
                             type_code,
                             HEADER_LEN,
                             HEADER_LEN + (len(data) if data else 0),
                             seq,
                             ack)
        content = header + (data if data else b'')
        self.sock.sendto(content, (self.hostname, self.port))
        if type_code == DATA:
            self.send_time_dict[seq] = time.time()

    def send_data(self):
        cnt = 0
        while len(self.send_seq_list) > 0 and cnt <= self.cwnd:
            seq = self.send_seq_list.pop()
            left = (seq - 1) * MAX_PAYLOAD
            right = min(seq * MAX_PAYLOAD, CHUNK_SIZE)
            self.send(DATA,
                      seq=seq,
                      data=self.send_chunk[left:right])
            if 0 < CONFIG.verbose: lprint(f"Sent data[{left}:{right}] to {self}")
            cnt += 1

    def receive_data(self, data: bytes, seq):
        if 0 < CONFIG.verbose: lprint(f"Received data[seq={seq}] from {self}")
        self.send(ACK, ack=seq)

    def receive_ack(self, ack):
        # estimate RTT
        sample_RTT = time.time() - self.send_time_dict[ack]
        self.estimated_RTT = (1 - self.alpha) * self.estimated_RTT + self.alpha * sample_RTT
        self.dev_RTT = (1 - self.beta) * self.dev_RTT + self.beta * abs(sample_RTT - self.estimated_RTT)
        self.timeout_interval = self.estimated_RTT + 4 * self.dev_RTT

        # stop expecting this ACK
        self.send_time_dict.pop(ack, None)

        # count duplicate ACKs
        if ack in self.ack_cnt_dict.keys():
            self.ack_cnt_dict[ack] += 1
            if self.ack_cnt_dict[ack] == 3:
                self.ack_cnt_dict[ack] = 0
                self.reset()
            else:
                return
        else:
            self.ack_cnt_dict[ack] = 1
            if self.cwnd >= self.ssthresh:  # Congestion Avoidance state
                self.cwnd = math.floor(self.cwnd + 1 / self.cwnd)
            else:  # Slow Start state
                self.cwnd += 1

        # finish or continue sending
        if CHUNK_SIZE <= ack * MAX_PAYLOAD:
            # TODO: possible conflict between two files
            self.free = True  # chunk transfer completed
            # verbose debug
            if 0 < CONFIG.verbose: lprint(f"Sent 1 chunk with ack: {ack}")
        else:
            self.send_seq_list.append(ack + 1)

    def expect_ack(self):
        for seq, send_time in self.send_time_dict.items():
            if send_time + self.timeout_interval <= time.time():
                self.send_seq_list.append(seq)
                self.reset()

    def reset(self):
        self.ssthresh = max(math.floor(self.cwnd / 2), 2)
        self.cwnd = 1


class Download:
    def __init__(self, chunk_file, output_file):
        with open(chunk_file, 'r') as file:
            self.requests = [line.strip().split(" ")[1] for line in file]
        self.received = dict()
        self.remaining = len(self.requests)
        self.output_file = output_file
        self.request_idx = 0

    def append_data(self, peer: Peer, data: bytes):
        """
        Appends a single packet's data to its corresponding chunk.

        :type peer: Peer
        :param peer: the peer sending the chunk
        :type data: bytes
        :param data: the data in the packet
        """
        if peer.receive_hash in self.received:
            self.received[peer.receive_hash] += data
        else:
            self.received[peer.receive_hash] = data
        if len(self.received[peer.receive_hash]) == CHUNK_SIZE:
            self.remaining -= 1
            CONFIG.haschunks[peer.receive_hash] = self.received[peer.receive_hash]
            self.dump()
            # verbose debug
            if 0 < CONFIG.verbose:
                sha1 = hashlib.sha1()
                sha1.update(self.received[peer.receive_hash])
                lprint(f"Received 1 chunk\n"
                       f"\texpected hash : {peer.receive_hash}\n"
                       f"\tgot hash      : {sha1.hexdigest()}")
            # clear the receiving indicator
            peer.receive_hash = ""

    def reset_broadcast(self):
        self.request_idx = 0

    def broadcast_request(self):
        """
        Broadcast the next request in a circular list to all peers.
        """
        if self.request_idx < len(self.requests):  # ensure that the index is in bound
            for _, peer in PEERS.items():
                peer.send(WHOHAS, data=bytes.fromhex(self.requests[self.request_idx]))
            # verbose debug
            if 0 < CONFIG.verbose: lprint(f"Routine broadcasting for {self.requests[self.request_idx]}")
            self.request_idx += 1  # prepare to broadcast the next request

    def remove_request(self, chunk_hash):
        self.requests.remove(chunk_hash)

    def append_request(self, chunk_hash):
        # ensure that no existing requests are appended
        if chunk_hash in self.requests:
            return
        self.requests.append(chunk_hash)
        # clear any previously received data
        if chunk_hash in self.received:
            self.received[chunk_hash] = b''
        # broad cast this new request
        for _, peer in PEERS.items():
            peer.send(WHOHAS, data=bytes.fromhex(chunk_hash))
        # verbose debug
        if 0 < CONFIG.verbose: lprint(f"Broadcasting for chunk {chunk_hash}")

    def completed(self):
        return self.remaining == 0

    def dump(self):
        """
        Dumps the received chunks to a file in dictionary format and prints "GOT".
        """
        with open(self.output_file, "wb") as file:
            pickle.dump(self.received, file)
        print(f"GOT {self.output_file}")


# global variables
PEERS = dict()
CONNECTION_CNT = 0
DOWNLOAD: Download = None
CONFIG: bt_utils.BtConfig = None


def process_inbound_udp(sock: simsocket.SimSocket):
    """
    Processes the UDP packet received.
    """
    packet, from_addr = sock.recvfrom(BUF_SIZE)
    magic, team, type_code, header_len, packet_len, seq, ack = struct.unpack("!HBBHHII", packet[:HEADER_LEN])
    data = packet[HEADER_LEN:]
    # get peer
    peer: Peer = PEERS[from_addr]
    # check magic value
    if magic != MAGIC_VAL:
        lprint(f"Magic value [{magic}] incorrect: endianness incorrect or packet is spoofed")
    # got WHOHAS
    if type_code == WHOHAS:
        # get the request chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 0 < CONFIG.verbose: lprint(f"Received WHOHAS requesting for [{chunk_hash}]\n"
                                      f"\thas: {list(CONFIG.haschunks.keys())}")
        if CONNECTION_CNT == CONFIG.max_conn:
            if 0 < CONFIG.verbose: lprint(f"Connection denied due to connection limit reached")
            peer.send(DENIED)  # denied
        elif chunk_hash in CONFIG.haschunks and peer.free:  # chunk needed and peer free
            if 0 < CONFIG.verbose: lprint(f"Trying to establish connection with {peer}")
            peer.send(IHAVE, data=data[:HASH_SIZE])  # send back the hash requested
            peer.send_chunk = CONFIG.haschunks[chunk_hash]  # prepare chunk to be sent
    # got IHAVE
    elif type_code == IHAVE:
        # get the sender's chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 0 < CONFIG.verbose: lprint(f"Received IHAVE with [{chunk_hash}] from {peer}\n"
                                      f"\tneeds: {list(DOWNLOAD.requests)}")
        if chunk_hash in DOWNLOAD.requests:
            if 0 < CONFIG.verbose: lprint(f"Agreed to establish connection with {peer}")
            DOWNLOAD.remove_request(chunk_hash)
            peer.receive_hash = chunk_hash  # hash for the chunk to be received
            peer.send(GET)
    # got GET
    elif type_code == GET:
        if 0 < CONFIG.verbose: lprint(f"Connection establish with {peer}")
        peer.free = False  # start sending send_chunk
        peer.send_seq_list.append(1)
    # got DATA
    elif type_code == DATA:
        peer.receive_data(data, seq)
        DOWNLOAD.append_data(peer, data)
    # got ACK
    elif type_code == ACK:
        peer.receive_ack(ack)
    # refresh connection if its a receiver or sender peer
    peer.connection_refresh()


def peer_run(config):
    address = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, address, verbose=config.verbose)

    Peer.sock = sock
    global PEERS, DOWNLOAD, CONFIG
    for (idx, hostname, port) in config.peers:
        idx, port = int(idx), int(port)
        if idx != config.identity:
            peer = Peer(idx, hostname, port)
            PEERS[(hostname, port)] = peer

    CONFIG = config
    CONFIG.verbose = 1

    request_timestamp = time.time()

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:  # a packet or input have been received
                if sock in read_ready:
                    request_timestamp = time.time()
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    # process user input
                    command, chunk_file, output_file = input().split(" ")
                    if command == 'DOWNLOAD':
                        DOWNLOAD = Download(chunk_file, output_file)
            for _, peer in PEERS.items():
                if not peer.free: peer.send_data()  # send data for connected peers
                if peer.connection_timeout(): peer.connection_reset()
                peer.expect_ack()
            if DOWNLOAD:
                if request_timestamp + REQUEST_TIMEOUT < time.time():
                    DOWNLOAD.reset_broadcast()
                    # verbose debug
                    if 0 < CONFIG.verbose: lprint(f"Broadcasting {DOWNLOAD.requests} due to request timeout")
                DOWNLOAD.broadcast_request()  # ask for a chunk
            # pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
