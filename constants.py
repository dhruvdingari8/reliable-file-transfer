from enum import IntEnum

SERVER_PORT = 6767
CLIENT_PORT = 7676
CHUNK_SIZE = 1400
WINDOW_SIZE = 16
TIMEOUT = 0.5


class Flag(IntEnum):
    DATA = 0x00
    ACK = 0x01
    REQUEST = 0x02
    FIN = 0x04

OUTPUT_DIR = "output/"
