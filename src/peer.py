import sys
import os
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
HEADER_LEN = struct.calcsize("HBBHHII")
MAGIC_VAL = 52305
TEAM_CODE = 28

# packet types
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5


class Peer:
    __sock = None

    def __init__(self, idx, hostname, port):
        self.idx, self.hostname, self.port = idx, hostname, port
        self.receive_hash = ""
        self.send_chunk = b''
        self.free = True

    def __str__(self):
        s = f"peer[{self.idx}] at {self.hostname}:{self.port}"
        return s

    @property
    def sock(self):
        return Peer.__sock

    @sock.setter
    def sock(self, sock: simsocket.SimSocket):
        Peer.__sock = sock

    def send(self, type_code: int, data: bytes = None):
        header = struct.pack("!HBBHHII",
                             socket.htons(52305),
                             TEAM_CODE,
                             type_code,
                             socket.htons(HEADER_LEN),
                             socket.htons(HEADER_LEN + (len(data) if data else 0)),
                             socket.htonl(0),
                             socket.htonl(0))
        self.sock.sendto(header + (data if data else b''), (self.hostname, self.port))

    def send_data(self):
        # TODO: RDT and Congestion
        pass

    def receive_data(self, data: bytes, seq):
        # TODO: RDT and Congestion
        pass

    def receive_ack(self, ack):
        # TODO: RDT and Congestion
        pass


class Download:
    def __init__(self, chunk_file, output_file):
        with open(chunk_file, 'r') as file:
            self.requests = [line.strip().split(" ")[1] for line in file]
        self.received = dict()
        self.remaining = len(self.requests)
        self.output_file = output_file
        self.request_idx = 0

    def append_data(self, chunk_hash, data: bytes):
        """
        Appends a single packet's data to its corresponding chunk.

        :type chunk_hash: str
        :param chunk_hash: the hash for the downloading chunk
        :type data: bytes
        :param data: the data in the packet
        """
        if chunk_hash in self.received:
            self.received[chunk_hash] += data
        else:
            self.received[chunk_hash] = data
        if len(self.received[chunk_hash]) == CHUNK_SIZE:
            self.remaining -= 1
            CONFIG.haschunks[chunk_hash] = self.received[chunk_hash]
            # verbose debug
            if 0 < CONFIG.verbose:
                sha1 = hashlib.sha1()
                sha1.update(self.received[chunk_hash])
                print(f"Received 1 chunk\n"
                        f"\texpected hash : {chunk_hash}\n"
                        f"\tgot hash      : {sha1.hexdigest()}")

    def broadcast_request(self):
        """
        Broadcast the next request in a circular list to all peers.
        """
        self.request_idx %= len(self.requests)  # ensure that the index is in bound
        for _, peer in PEERS.items():
            peer.send(WHOHAS, bytes.fromhex(self.requests[self.request_idx]))
        self.request_idx += 1  # prepare to broadcast the next request

    def remove_request(self, chunk_hash):
        self.requests.remove(chunk_hash)

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
CONFIG = None


def process_inbound_udp(sock: simsocket.SimSocket):
    """
    Processes the UDP packet received.
    """
    packet, from_addr = sock.recvfrom(BUF_SIZE)
    # TODO: RDT and Congestion (new fields if needed)
    magic, team, type_code, header_len, packet_len, seq, ack = struct.unpack("!HBBHHII", packet[:HEADER_LEN])
    data = packet[HEADER_LEN:]
    # get peer
    peer: Peer = PEERS[from_addr]
    # check magic value
    if magic != MAGIC_VAL:
        print(f"Magic value [{magic}] incorrect: endianness incorrect or packet is spoofed")
    # got WHOHAS
    if type_code == WHOHAS:
        # get the request chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 0 < CONFIG.verbose: print(f"Received WHOHAS requesting for [{chunk_hash}]\n"
                                     f"\thas: {list(CONFIG.haschunks.keys())}")
        if CONNECTION_CNT == CONFIG.max_conn:
            if 0 < CONFIG.verbose: print(f"Connection denied due to connection limit reached")
            peer.send(DENIED)  # denied
        elif chunk_hash in CONFIG.haschunks and peer.free:  # chunk needed and peer free
            if 0 < CONFIG.verbose: print(f"Trying to establish connection with {peer}")
            peer.send(IHAVE, data[:HASH_SIZE])  # send back the hash requested
            peer.send_chunk = CONFIG.haschunks[chunk_hash]  # prepare chunk to be sent
    # got IHAVE
    elif type_code == IHAVE:
        # get the sender's chunk's hash
        chunk_hash = bytes.hex(data[:HASH_SIZE])
        # verbose debug
        if 0 < CONFIG.verbose: print(f"Received IHAVE with [{chunk_hash}]\n"
                                     f"\tneeds: {list(DOWNLOAD.requests)}")
        if chunk_hash in DOWNLOAD.requests:
            if 0 < CONFIG.verbose: print(f"Agreed to establish connection with {peer}")
            DOWNLOAD.remove_request(chunk_hash)
            peer.receive_hash = chunk_hash  # hash for the chunk to be received
            peer.send(GET)
    # got GET
    elif type_code == GET:
        if 0 < CONFIG.verbose: print(f"Connection establish with {peer}")
        peer.free = False  # start sending send_chunk
        peer.send_data()
    # got DATA
    elif type_code == DATA:
        # TODO: RDT and Congestion
        peer.receive_data(data, socket.ntohl(seq))
        DOWNLOAD.append_data(peer.receive_hash, data)
    # got ACK
    elif type_code == ACK:
        # TODO: RDT and Congestion
        ack = socket.ntohl(ack)
        peer.receive_ack(ack)
        if CHUNK_SIZE <= ack:
            peer.free = True  # chunk transfer completed
            # verbose debug
            if 0 < CONFIG.verbose: print(f"Sent 1 chunk with hash: {peer.chunk_hash}")


def peer_run(config):
    address = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, address, verbose=config.verbose)

    Peer.sock = sock
    global PEERS, DOWNLOAD
    for (idx, hostname, port) in config.peers:
        idx, port = int(idx), int(port)
        if idx != config.identity:
            peer = Peer(idx, hostname, port)
            PEERS[(hostname, port)] = peer

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:  # a packet or input have been received
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    # process user input
                    command, chunk_file, output_file = input().split(" ")
                    if command == 'DOWNLOAD':
                        DOWNLOAD = Download(chunk_file, output_file)
            else:  # free to send packets
                if DOWNLOAD: DOWNLOAD.broadcast_request()  # ask for a chunk
                for _, peer in PEERS.items():
                    if not peer.free: peer.send_data()  # send data for connected peers
                pass
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

    CONFIG = bt_utils.BtConfig(args)
    peer_run(CONFIG)
