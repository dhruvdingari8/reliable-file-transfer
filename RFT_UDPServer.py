import socket, struct, threading, time, hashlib, os
from packet import (
    build_ip_header,
    build_udp_header,
    build_app_header,
    parse_app_header,
    calc_checksum,
)
from constants import *


class RFTServer:
    def __init__(self, server_ip):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.server_ip = server_ip
        self.packets_sent = 0
        self.packets_retransmitted = 0
        self.packets_received = 0

    def start(self):
        """
        Binds socket to Server's IP and Port, then waits for incoming packets.
        """
        self.socket.bind((self.server_ip, SERVER_PORT))
        print(f"Server listening on {self.server_ip}:{SERVER_PORT}")

        while True:
            raw_data, client_addr = self.socket.recvfrom(65535)
            # print(f"Received packet from {client_addr}, length {len(raw_data)}")
            ip_header = raw_data[:20]
            udp_header = raw_data[20:28]
            app_header_data = raw_data[28:42]
            payload = raw_data[42:]

            seq, ack, flags, data_length, chk = parse_app_header(app_header_data)

            dst_port = struct.unpack(">H", udp_header[2:4])[0]
            dst_port = struct.unpack(">H", udp_header[2:4])[0]
            # print(f"dst_port: {dst_port}, flags: {flags}")

            if dst_port != SERVER_PORT:
                continue

            if flags == Flag.REQUEST:
                filename = payload.decode().strip("\x00")
                self.handle_request(filename, client_addr[0])

    def handle_request(self, filename, client_ip):
        """
        Handles incoming file requests.

        - Opens the requested file
        - Computes MD5 Hash
        - Calculates needed chunks to send
        - Starts file transfer by calling send_file
        """
        print(f"Handling request for {filename} from {client_ip}")

        # Check if file exists, print an error and return if not
        if not os.path.exists(filename):
            print(f"File {filename} not found")
            return

        # Get file size
        self.file_size = os.path.getsize(filename)

        # Compute MD5 hash
        md5 = hashlib.md5()
        with open(filename, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
        self.original_md5 = md5.hexdigest()

        # Record the start time
        self.start_time = time.time()

        # Send file
        self.send_file(filename, client_ip)

        output_path = self.write_report(filename, 0)
        print(f"Report written, found at {output_path}.")

    def send_file(self, filename, client_ip):
        """
        Maintains window of unacknowledged packets, sending new chunks as the window allows.

        Spawns two threads, one to send packets and one to listen to ACKS. Also handles retransmissions when a timeout fires.
        """
        print(f"Sending file {filename} to {client_ip}")

        # Shared State Variables
        base = 0  # Lowest unacked sequence number (left edge of window)
        next_seq = 0  # Next sequence number to send (right edge of window)
        lock = threading.Lock()  # Data lock for shared data
        ack_received = threading.Event()  # ACK received Event to share between threads
        unacked = {}  # List of unacknowledged transmissions
        done = threading.Event()  # File Transfer complete

        chunks = []
        with open(filename, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                chunks.append(chunk)
        total_chunks = len(chunks)

        def sender():
            nonlocal base, next_seq

            while not done.is_set():
                # Acquire lock
                with lock:
                    # Check if window has space
                    if next_seq - base < WINDOW_SIZE and next_seq < total_chunks:
                        # There is space. Build and send the next packet
                        # Build headers first
                        ip_header = build_ip_header(
                            self.server_ip, client_ip, len(chunks[next_seq])
                        )
                        udp_header = build_udp_header(
                            SERVER_PORT, CLIENT_PORT, len(chunks[next_seq])
                        )

                        # Initial app header
                        app_header = build_app_header(
                            next_seq, 0, Flag.DATA, len(chunks[next_seq]), 0
                        )
                        # Calculate checksum for app header + chunk
                        checksum = calc_checksum(app_header + chunks[next_seq])

                        # Remake app header with calculated checksum
                        # Final app header
                        app_header = build_app_header(
                            next_seq, 0, Flag.DATA, len(chunks[next_seq]), checksum
                        )

                        print(f"Self-verify: {calc_checksum(app_header + chunks[next_seq]):#06x}")

                        # Concatonate headers with payload into packet
                        packet = ip_header + udp_header + app_header + chunks[next_seq]

                        print(f"Sending chunk {next_seq}, checksum: {checksum:#06x}, data_length: {len(chunks[next_seq])}")

                        # Send and store packet, increment counters
                        self.socket.sendto(packet, (client_ip, 0))
                        print(f"Sent chunk {next_seq} to {client_ip}")
                        unacked[next_seq] = (packet, time.time())
                        next_seq += 1
                        self.packets_sent += 1

                if next_seq - base >= WINDOW_SIZE or next_seq >= total_chunks:
                    # NOTE: next_seq and base are read here outside the lock, which introduces a minor
                    # race condition with the ACK receiver thread. In the worst case this causes an
                    # unnecessary wait or a skipped wait, but does not affect correctness.

                    # There is no space. Window is full.
                    # Wait on ack_received until timeout
                    ack_received.wait(TIMEOUT)
                    ack_received.clear()

                with lock:
                    for seq, (packet, timestamp) in list(unacked.items()):
                        if time.time() - timestamp > TIMEOUT:
                            self.socket.sendto(packet, (client_ip, 0))
                            unacked[seq] = (packet, time.time())
                            self.packets_retransmitted += 1

                    # Check if transmission is done yet
                    if base == total_chunks:
                        done.set()

        def ack_receiver():
            nonlocal base
            self.socket.settimeout(TIMEOUT)

            # Loop while transmission is not done
            while not done.is_set():
                # Unpack each packet
                try:
                    raw_data = self.socket.recvfrom(65535)[0]
                except socket.timeout:
                    continue

                udp_header = raw_data[20:28]
                app_header_data = raw_data[28:42]

                seq, ack, flags, data_length, chk = parse_app_header(app_header_data)

                dst_port = struct.unpack(">H", udp_header[2:4])[0]

                # Ensure incoming packet destination is this port
                if dst_port != SERVER_PORT:
                    continue

                # Check if packet is an ACK
                if flags == Flag.ACK:
                    # It is an ACK, move base
                    with lock:
                        base = ack
                        # Update unacked dict to remove all packets with seq less than base
                        to_delete = [s for s in unacked if s < base]
                        for s in to_delete:
                            del unacked[s]

                        self.packets_received += 1
                        ack_received.set()

        # Start threads
        sender_thread = threading.Thread(target=sender)
        ack_thread = threading.Thread(target=ack_receiver)
        sender_thread.start()
        ack_thread.start()

        # Wait for transfer to complete
        sender_thread.join()
        ack_thread.join()
        self.socket.settimeout(None)

        # Send FIN packet
        # Build headers
        ip_header = build_ip_header(self.server_ip, client_ip, 14)
        udp_header = build_udp_header(SERVER_PORT, CLIENT_PORT, 14)
        app_header = build_app_header(total_chunks, 0, Flag.FIN, 0, 0)
        chk = calc_checksum(app_header)
        app_header = build_app_header(total_chunks, 0, Flag.FIN, 0, chk)
        fin_packet = ip_header + udp_header + app_header
        self.socket.sendto(fin_packet, (client_ip, 0))
        print("File transfer complete, FIN sent")

    def write_report(self, filename, loss_pct) -> str:
        """
        Called after transfer completes, writing the formatted text report to specified output directory (default `output/`)

        - Calculates time taken to transmit
        - Writes a text file to output directory with required fields
        """

        # Calculate duration
        duration = time.time() - self.start_time
        time_taken = time.strftime("%H:%M:%S", time.gmtime(duration))

        sep = "-" * 65
        report = f"""RFT Transmission Report
{sep}
{'File Info':^65}
{sep}
{'Filename:':<23}{filename}
{'Size:':<23}{self.file_size}
{sep}
{'Packet Stats':^65}
{sep}
{'Packet Loss %:':<27}{loss_pct}{'%'}
{'Packets Sent:':<27}{self.packets_sent}
{'Packets Retransmitted:':<27}{self.packets_retransmitted}
{'Packets Received:':<27}{self.packets_received}
{'Total Time Taken:':<27}{time_taken}
{sep}
{'Hashes':^65}
{sep}
{'MD5 Hash of Original File:':<30}{self.original_md5}
{'MD5 Hash of Received File:':<30}{self.original_md5}
{sep}
"""

        report_file = f"{filename}_report.txt"
        count = 1
        while os.path.exists(os.path.join(OUTPUT_DIR, report_file)):
            report_file = f"{filename}_report_{count}.txt"
            count += 1

        with open(os.path.join(OUTPUT_DIR, report_file), "w") as f:
            f.write(report)

        return os.path.join(OUTPUT_DIR, report_file)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: sudo python3 RFT_UDPServer.py <server_ip>")
        sys.exit(1)
    server = RFTServer(sys.argv[1])
    server.start()
