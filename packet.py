import struct, socket


def calc_checksum(byte_string: bytes) -> int:
    """
    Calculate the checksum of a byte string.
    """

    # Pad byte string ensure even length
    if len(byte_string) % 2 != 0:
        byte_string += b"\x00"

    # Sum all 16-bit words
    total = 0
    for i in range(0, len(byte_string), 2):
        word = struct.unpack(">H", byte_string[i : i + 2])[0]
        total += word

    # Fold overflow
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)

    result = ~total & 0xFFFF
    return 0xFFFF if result == 0 else result

def build_ip_header(src_ip: str, dst_ip: str, data_length: int) -> bytes:
    """
    Build the header of an IP dataframe based on parameters.
    """

    def pack_ip_header(
        version, tos, total_length, id, flags, ttl, protocol, chk, source_ip, dest_ip
    ) -> bytes:
        """
        Helper function to pack IP header
        """

        return (
            struct.pack(
                ">BBHHHBBH", version, tos, total_length, id, flags, ttl, protocol, chk
            )
            + source_ip
            + dest_ip
        )

    header = pack_ip_header(
        version = 0x45,
        tos = 0,
        total_length = (20 + data_length),
        id = 0,
        flags = 0,
        ttl = 64,
        protocol = socket.IPPROTO_UDP,
        chk = 0,
        source_ip = socket.inet_aton(src_ip),
        dest_ip= socket.inet_aton(dst_ip)
    )
    checksum = calc_checksum(header)
    header = pack_ip_header(
        version = 0x45,
        tos = 0,
        total_length = (20 + data_length),
        id = 0,
        flags = 0,
        ttl = 64,
        protocol = socket.IPPROTO_UDP,
        chk = checksum,
        source_ip = socket.inet_aton(src_ip),
        dest_ip= socket.inet_aton(dst_ip)
    )

    return header


def build_udp_header(src_port: int, dst_port: int, data_length: int) -> bytes:
    """
    Build the header of the UDP packet.
    """
    
    length = 8 + data_length
    checksum = 0

    header = struct.pack(">HHHH", src_port, dst_port, length, checksum)

    return header

def build_app_header(seq: int, ack: int, flags: int, data_length: int, chk: int) -> bytes:
    """
    Builds the header of an application
    """
    
    header = struct.pack(">IIBxHH", seq, ack, flags, data_length, chk)
    return header

def parse_app_header(data: bytes) -> tuple:
    """
    Parses the header of an application into a tuple.
    """

    return struct.unpack(">IIBxHH", data[:14])