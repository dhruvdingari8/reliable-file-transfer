import socket, struct, time, hashlib, os
from packet import build_ip_header, build_udp_header, build_app_header, parse_app_header, calc_checksum
from constants import *

class RFTClient:
    def __init__(self, client_ip, server_ip):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.server_ip = server_ip
        self.client_ip = client_ip
        self.received_chunks = {}

    def request_file(self, filename):
        """
        Sends a file request packet to the server ip.
        """
        
        # Build a packet
        # Payload
        payload = filename.encode()
        # Headers
        headers = self._build_headers(len(payload))
        app_header = build_app_header(0, 0, Flag.REQUEST, len(payload), 0)

        # Recalculate checksum and rebuild packet
        checksum = calc_checksum(app_header + payload)
        app_header = build_app_header(0, 0, Flag.REQUEST, len(payload), checksum)
        
        # Concatonate together to form inital packet
        packet = headers + app_header + payload

        self.socket.sendto(packet, (self.server_ip, 0))
        # print(f"File Request for file {filename} sent to IP {self.server_ip}")

        # Receive file packets
        self.receive_file(filename)

    def receive_file(self, filename):
        """
        Continuously checks for incoming file chunk packets.
        """
        expected_seq = 0
        
        # Loop waiting for packets
        while True:
            packet, addr = self.socket.recvfrom(65535)
            # print(f"Client received packet from {addr}, length {len(packet)}")
            # Parse incoming app header
            ip_header = packet[:20]
            udp_header = packet[20:28]
            app_header_data = packet[28:42]
            
            seq, ack, flags, data_length, chk = parse_app_header(app_header_data)
            src_ip = socket.inet_ntoa(packet[12:16])
            
            # if src_ip == self.server_ip:
            #     print(f"Client parsed: seq={seq}, flags={flags}, data_length={data_length}, chk={chk:#06x}")

            payload = packet[42:42 + data_length]


            dst_port = struct.unpack(">H", udp_header[2:4])[0]

            # Filter Packets
            # Check if destination is this port
            if dst_port != CLIENT_PORT:
                # if not, skip and keep looping
                continue

            # Verify checksum
            if (calc_checksum(app_header_data + payload) != 0xFFFF):
                print(f"Checksum failed: {calc_checksum(app_header_data + payload):#06x}")
                continue
            
            # Check if flag is one of: DATA, FIN
            match flags:
                case Flag.DATA:
                    # If DATA, store chunk and send cumulative ACK
                    self.received_chunks[seq] = payload
                    while expected_seq in self.received_chunks:
                        expected_seq += 1
                    self.send_ack(expected_seq)
                case Flag.FIN:
                    # If FIN, break loop and reassemble file
                    break
        
        self.reassemble_file(filename)

    def send_ack(self, ack_num):
        """
        Sends an ACK packet back to the server in response to a successful file chunk received.
        """

        # Build a packet with ACK flag
        # Get IP and UDP headers
        headers = self._build_headers(0)
        # Build initial app header
        app_header = build_app_header(0, ack_num, Flag.ACK, 0, 0)
        # Calculate checksum and rebuild headers
        checksum = calc_checksum(app_header)
        app_header = build_app_header(0, ack_num, Flag.ACK, 0, checksum)
        # Concatonate packet
        packet = headers + app_header
        # Send packet
        self.socket.sendto(packet, (self.server_ip, 0))

    def reassemble_file(self, filename):
        with open(f"received_{filename}", "wb") as f:
            for seq in sorted(self.received_chunks.keys()):
                f.write(self.received_chunks[seq])

        # Computer MD5 hash
        md5 = hashlib.md5()
        with open(f"received_{filename}", "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
        self.md5 = md5.hexdigest()
        print(f"Computed MD5 Hash: {self.md5}")


    def _build_headers(self, data_len) -> bytes:
        # Headers
        ip_header = build_ip_header(self.client_ip, self.server_ip, 8 + 14 + data_len)
        udp_header = build_udp_header(CLIENT_PORT, SERVER_PORT, 14 + data_len)
        headers = ip_header + udp_header
        return headers


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: sudo python3 RFT_UDPClient.py <client_ip> <server_ip> <filename>")
        sys.exit(1)
    client = RFTClient(sys.argv[1], sys.argv[2])
    client.request_file(sys.argv[3])
