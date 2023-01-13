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
CHUNK_SPAN = 512
HASH_SIZE = 20
HEADER_LEN = struct.calcsize("!HBBHHII")
MAGIC_VAL = 52305
MAX_PAYLOAD = 1024
TEAM_CODE = 28
CONNECTION_TIMEOUT = 40
CONNECTION_DELAY = 100
REQUEST_TIMEOUT = 60
ACK_DELAY = 0.1
RTT_INIT = 1

# packet types
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

# global variables
receiver_cnt = 0

# verbose functions
from contextlib import redirect_stdout
init = True
time_base = 0
def lprint(*args, **kwargs):
    # print(*args, file=sys.stderr, **kwargs)
    # print(*args, **kwargs)
    global init, time_base
    if init:
        init = False
        time_base = time.time()
        with open(f"./log/comp-{CONFIG.identity}.log", 'w+') as f:
            with redirect_stdout(f):
                print(get_time(), *args, **kwargs)
    else:
        with open(f"./log/comp-{CONFIG.identity}.log", 'a') as f:
            with redirect_stdout(f):
                print(get_time(), *args, **kwargs)
    pass


def get_time():
    if 2 < CONFIG.verbose: return f"time: {time.time() - time_base:10f}s  "
    return ""


class Peer:
    __sock = None

    def __init__(self, idx, hostname, port):
        self.idx, self.hostname, self.port = idx, hostname, port
        self.receive_hash = ""
        self.send_chunk = b''
        self.send_seq_list = []
        self.free = True
        self.connection_timestamp = 0
        self.buffer: Buffer = Buffer()

        # timeout variables
        self.timeout_interval = RTT_INIT
        self.estimated_RTT = 0.0
        self.dev_RTT = 0.0
        self.alpha = 0.125
        self.beta = 0.25
        self.send_time_dict = dict()

        # duplicate ACKs && congestion control variables
        self.ack_cnt_dict = dict()
        self.cwnd = 1
        self.ssthresh = 64

        # sender
        self.send_base = 0
        self.next_seq = 0
        self.timer = 0
        self.timed_ack = 0
        # receiver
        self.next_ack = 1
        self.prev_ack_at = 0
        self.delay_ack = False
        self.receive_bound = 0

    def __str__(self):
        s = f"peer[{self.idx:2d}] at {self.hostname}:{self.port}"
        return s

    @property
    def sock(self):
        return Peer.__sock

    @sock.setter
    def sock(self, sock: simsocket.SimSocket):
        Peer.__sock = sock

    def init_send(self):
        global receiver_cnt
        self.free = False  # start sending send_chunk
        receiver_cnt += 1
        self.send_seq_list.append(1)

    def close_send(self):
        global receiver_cnt
        receiver_cnt -= 1
        # verbose debug
        if 2 < CONFIG.verbose: lprint(f"Stopped sending to {self}")
        self.connection_timestamp = 0
        self.free = True

        self.timeout_interval = RTT_INIT
        self.estimated_RTT = 0.0
        self.dev_RTT = 0.0
        self.alpha = 0.125
        self.beta = 0.25
        self.send_time_dict.clear()

        self.ack_cnt_dict.clear()
        self.cwnd = 1
        self.ssthresh = 64

        self.send_base = 0
        self.next_seq = 0
        self.timer = 0
        self.timed_ack = 0

    def init_receive(self, chunk_hash):
        DOWNLOAD.remove_request(chunk_hash)
        self.receive_hash = chunk_hash  # hash for the chunk to be received

    def close_receive(self, success=False):
        # verbose debug
        if 2 < CONFIG.verbose:
            result = "Success" if success else "Stopped"
            lprint(f"{result} receiving {self.receive_hash} from {self}")
        if not success:
            DOWNLOAD.append_request(self.receive_hash)  # not successful, try again
        self.connection_timestamp = 0
        self.receive_hash = ""
        self.buffer.empty()

        self.next_ack = 1
        self.prev_ack_at = 0
        self.delay_ack = False
        self.receive_bound = 0

    def refresh_all(self):
        if self.receive_hash or not self.free:
            self.connection_timestamp = time.time()

    def timeout_all(self):
        return (self.receive_hash or not self.free) and \
                self.connection_timestamp + \
               (CONNECTION_TIMEOUT if self.timeout_interval == RTT_INIT else CONNECTION_DELAY * self.timeout_interval) \
               < time.time()

    def close_all(self):
        if self.receive_hash:
            self.close_receive()
        elif not self.free:
            self.close_send()

    def send_packet(self, type_code: int, seq: int = 0, ack: int = 0, data: bytes = None):
        if type_code == DATA and seq: data = self.send_chunk[(seq - 1) * MAX_PAYLOAD:seq * MAX_PAYLOAD]
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
        if 2 < CONFIG.verbose:
            if type_code == ACK: lprint(f"Sent*    ACK [ack={ack:3d}] to {self}")
            if type_code == DATA: lprint(f"Sent*    DATA[seq={seq:3d}] to {self}")

    def send_data(self):
        if self.free: return
        # send all packets in the window and advance the send pointer
        if self.next_seq < self.send_base + math.floor(self.cwnd) and self.next_seq <= CHUNK_SPAN:
            self.next_seq += 1
            self.send_packet(DATA, self.next_seq)

            if not self.timer:
                self.timer = time.time()
                self.timed_ack = self.next_seq
                if 2 < CONFIG.verbose: lprint(f"Ack {self.next_seq} is timed")

            if 1 < CONFIG.verbose:
                lprint(f"progress|{self.port}|{self.next_seq}|{(time.time() - time_base if time_base != 0 else 0)}")
                lprint(f"window_size|{self.port}|{self.cwnd}|{(time.time() - time_base if time_base != 0 else 0)}")
                lprint(f"rtt|{self.port}|{self.timeout_interval}|{(time.time() - time_base if time_base != 0 else 0)}")

            if 2 < CONFIG.verbose:
                lprint(f"Sent     DATA[seq={self.next_seq:3d}][base={self.send_base:3d}][next={self.next_seq:3d}] to   {self}")

    def receive_data(self, data: bytes, seq):
        if not self.receive_hash: return
        # try to insert the data into the buffer
        self.buffer.insert(data, seq)
        # the buffer is complete
        if self.buffer.size() == CHUNK_SPAN:
            self.send_packet(ACK, ack=CHUNK_SPAN)
            DOWNLOAD.append_buffer(self.buffer, self.receive_hash)
            self.close_receive(success=True)
            return

        # note the largest seq received (used to account for gaps)
        if self.receive_bound < seq: self.receive_bound = seq

        if self.next_ack == seq:
            self.next_ack += 1  # advance the receive pointer
            self.send_packet(ACK, ack=seq)

            # if self.delay_ack: self.send_packet(ACK, ack=seq)  # previously delayed
            # else: self.prev_ack_at = time.time()
            #
            # self.delay_ack = not self.delay_ack  # every other normal ACK
        else:
            if self.buffer.size() == self.receive_bound:  # filled the gap
                self.next_ack = self.receive_bound + 1  # advance to the bound
                self.send_packet(ACK, ack=self.receive_bound)
            else:
                self.send_packet(ACK, ack=self.next_ack)  # hope to trigger retransmit

        if 2 < CONFIG.verbose:
            lprint(f"Received DATA[seq={seq:3d}][bound={self.receive_bound:3d}][next={self.next_ack:3d}] from {self}")

    def send_ack(self):
        if self.prev_ack_at + ACK_DELAY < time.time():
            self.send_packet(ACK, ack=self.next_ack)
            self.delay_ack = False

    def receive_ack(self, ack):
        # estimate RTT
        if ack == self.timed_ack:
            if 2 < CONFIG.verbose: lprint(f"Timed ack {self.timed_ack} is received")
            sample_RTT = time.time() - self.timer
            self.estimated_RTT = (1 - self.alpha) * self.estimated_RTT + self.alpha * sample_RTT
            self.dev_RTT = (1 - self.beta) * self.dev_RTT + self.beta * abs(sample_RTT - self.estimated_RTT)
            self.timeout_interval = self.estimated_RTT + 4 * self.dev_RTT
            self.timed_ack = 0
            self.timer = 0

        # advance send base for cumulative ACK
        if self.send_base < ack:
            self.send_base = min(ack, CHUNK_SPAN - math.floor(self.cwnd))
            if self.send_base < self.next_seq:
                self.timed_ack = ack + 1
                self.timer = time.time()  # there are still unACKed packets
            else:
                self.timed_ack = 0
                self.timer = 0  # all packets are ACKed

        if 2 < CONFIG.verbose:
            lprint(f"Received ACK [ack={ack:3d}][base={self.send_base:3d}][next={self.next_seq:3d}] from {self}")

        # count duplicate ACKs
        if ack in self.ack_cnt_dict.keys():
            self.ack_cnt_dict[ack] += 1
            if self.ack_cnt_dict[ack] == 3:
                self.ack_cnt_dict[ack] = 0
                self.send_packet(DATA, seq=ack)
                self.reset_window()
            else:
                return
        else:
            self.ack_cnt_dict[ack] = 1
            if self.cwnd >= self.ssthresh:  # Congestion Avoidance state
                self.cwnd = self.cwnd + 1 / self.cwnd
            else:  # Slow Start state
                self.cwnd += 1

        # finish or continue sending
        if CHUNK_SPAN <= ack:
            self.close_send()
            # verbose debug
            if 2 < CONFIG.verbose: lprint(f"Sent 1 chunk with ack: {ack}")

    def expect_ack(self):
        if self.timer and self.timer + self.timeout_interval < time.time():
            # verbose debug
            if 2 < CONFIG.verbose: lprint(f"Timer timeout for {self}")
            self.reset_window()
            self.send_packet(DATA, seq=self.send_base + 1)
            self.timer = time.time()

    def reset_window(self):
        self.ssthresh = max(math.floor(self.cwnd / 2), 2)
        self.cwnd = 1


class Buffer:
    def __init__(self):
        self.data: List[bytes] = [b'' for _ in range(CHUNK_SPAN)]
        self.seqs = []

    def insert(self, data: bytes, seq: int):
        if seq in self.seqs: return  # duplicate data
        if 2 < CONFIG.verbose: lprint(f"Inserted DATA[seq={seq:3d}] into buffer, total seqs {len(self.seqs)+1}")
        self.seqs.append(seq)
        self.data[seq - 1] = data

    def size(self):
        return len(self.seqs)

    def dump(self):
        return b''.join(self.data)

    def empty(self):
        self.data = [b'' for _ in range(CHUNK_SPAN)]
        self.seqs.clear()


class Download:
    def __init__(self, chunk_file, output_file):
        with open(chunk_file, 'r') as file:
            self.requests = [line.strip().split(" ")[1] for line in file]
        self.received = dict()
        self.remaining = len(self.requests)
        self.output_file = output_file
        self.request_idx = 0

    def append_buffer(self, buffer: Buffer, chunk_hash: str):
        """
        Appends a single packet's data to its corresponding chunk.

        :type buffer: Buffer
        :param buffer: the buffer holding all the packets
        :type chunk_hash: str
        :param chunk_hash: the hash for the chunk being received
        """
        # ensure that no chunk is received twice
        if chunk_hash in self.received:
            return

        self.received[chunk_hash] = buffer.dump()
        self.remaining -= 1
        CONFIG.haschunks[chunk_hash] = self.received[chunk_hash]

        if self.remaining == 0: self.dump()  # dump when completed

        # verbose debug
        if 2 < CONFIG.verbose:
            sha1 = hashlib.sha1()
            sha1.update(self.received[chunk_hash])
            lprint(f"Completed a chunk with {len(buffer.data)} packets\n"
                   f"\texpected hash : {chunk_hash}\n"
                   f"\tgot hash      : {sha1.hexdigest()}")

    def reset_broadcast(self):
        self.request_idx = 0

    def broadcast_request(self):
        """
        Broadcast the next request in a circular list to all peers.
        """
        if self.request_idx < len(self.requests):  # ensure that the index is in bound
            for _, peer in PEERS.items():
                peer.send_packet(WHOHAS, data=bytes.fromhex(self.requests[self.request_idx]))
            # verbose debug
            if 2 < CONFIG.verbose: lprint(f"Routine broadcasting for {self.requests[self.request_idx]}")
            self.request_idx += 1  # prepare to broadcast the next request

    def remove_request(self, chunk_hash):
        self.requests.remove(chunk_hash)
        if self.request_idx: self.request_idx -= 1

    def append_request(self, chunk_hash):
        # ensure that no existing requests are appended
        if chunk_hash in self.requests:
            return
        self.requests.append(chunk_hash)
        # broad cast this new request
        for _, peer in PEERS.items():
            peer.send_packet(WHOHAS, data=bytes.fromhex(chunk_hash))
        # verbose debug
        if 2 < CONFIG.verbose: lprint(f"Broadcasting for chunk {chunk_hash}")

    def completed(self):
        return self.remaining == 0

    def dump(self):
        """
        Dumps the received chunks to a file in dictionary format and prints "GOT".
        """
        # verbose debug
        if 2 < CONFIG.verbose: lprint(f"Dumping received chunks")
        with open(self.output_file, "wb") as file:
            pickle.dump(self.received, file)
        print(f"GOT {self.output_file}")
        if 2 < CONFIG.verbose: lprint(f"Dumping completed")


# global variables
PEERS = dict()
DOWNLOAD: Download = None
CONFIG: bt_utils.BtConfig = None

CODE = ["WHOHAS", "IHAVE", "GET", "DATA", "ACK", "DENIED"]


def process_inbound_udp(sock: simsocket.SimSocket):
    """
    Processes the UDP packet received.
    """
    global receiver_cnt
    packet, from_addr = sock.recvfrom(BUF_SIZE)
    magic, team, type_code, header_len, packet_len, seq, ack = struct.unpack("!HBBHHII", packet[:HEADER_LEN])
    data = packet[HEADER_LEN:]
    # get peer
    peer: Peer = PEERS[from_addr]
    # if 2 < CONFIG.verbose: lprint(f"Received {CODE[type_code]}")
    # check magic value
    if magic != MAGIC_VAL:
        lprint(f"Magic value [{magic}] incorrect: endianness incorrect or packet is spoofed")
    # got WHOHAS
    if type_code == WHOHAS:
        # get the request chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 2 < CONFIG.verbose: lprint(f"Received WHOHAS requesting for [{chunk_hash}] from {peer}\n"
                                      f"\thas: {list(CONFIG.haschunks.keys())}")
        if receiver_cnt == CONFIG.max_conn:
            if 2 < CONFIG.verbose: lprint(f"Connection denied due to connection limit reached")
            peer.send_packet(DENIED)  # denied
        elif chunk_hash in CONFIG.haschunks and peer.free:  # chunk needed and peer free
            if 2 < CONFIG.verbose: lprint(f"Trying to establish connection with {peer}")
            peer.send_packet(IHAVE, data=data[:HASH_SIZE])  # send back the hash requested
            peer.send_chunk = CONFIG.haschunks[chunk_hash]  # prepare chunk to be sent
    # got IHAVE
    elif type_code == IHAVE:
        # get the sender's chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 2 < CONFIG.verbose: lprint(f"Received IHAVE with [{chunk_hash}] from {peer}\n"
                                      f"\tneeds: {list(DOWNLOAD.requests)}")
        if chunk_hash in DOWNLOAD.requests:
            if 2 < CONFIG.verbose: lprint(f"Agreed to establish connection with {peer}")
            peer.init_receive(chunk_hash)
            peer.send_packet(GET)
    # got GET
    elif type_code == GET:
        if 2 < CONFIG.verbose: lprint(f"Connection establish with {peer}")
        peer.init_send()
    # got DATA
    elif type_code == DATA:
        peer.receive_data(data, seq)
    # got ACK
    elif type_code == ACK:
        peer.receive_ack(ack)
    # refresh all connections for both receiver and sender peer
    peer.refresh_all()


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
    CONFIG.verbose = 2

    request_timestamp = time.time()

    try:
        while True:
            # start = time.time()

            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:  # a packet or input have been received

                # now = time.time()
                # lprint(f"Enter ready: {now - start}")
                # start = now

                if sock in read_ready:
                    request_timestamp = time.time()
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    # process user input
                    command, chunk_file, output_file = input().split(" ")
                    if command == 'DOWNLOAD':
                        DOWNLOAD = Download(chunk_file, output_file)

            # now = time.time()
            # lprint(f"Exit ready : {now - start}")
            # start = now

            for _, peer in PEERS.items():
                if not peer.free: peer.send_data()  # send DATA for connected peers
                # if peer.delay_ack: peer.send_ack()  # send delayed normal ACKs
                if peer.timeout_all(): peer.close_all()
                peer.expect_ack()

            # now = time.time()
            # lprint(f"Exit peers : {now - start}")
            # start = now

            if DOWNLOAD:
                if request_timestamp + REQUEST_TIMEOUT < time.time():
                    DOWNLOAD.reset_broadcast()
                    request_timestamp = time.time()
                    # verbose debug
                    if 2 < CONFIG.verbose: lprint(f"Broadcast reset due to request timeout")
                DOWNLOAD.broadcast_request()  # ask for a chunk

            # lprint(f"Exit loop  : {time.time() - start}")
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
