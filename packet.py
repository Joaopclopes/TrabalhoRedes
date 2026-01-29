import struct
import json
from cryptography.fernet import Fernet

# Configurações Globais
MSS = 1024  # Tamanho máximo do segmento (bytes de payload)
HEADER_FORMAT = '!IIH' # SeqNum (4), AckNum (4), Flags (2) - Usando struct
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Flags
SYN = 1
ACK = 2
FIN = 4
DATA = 8

class PacketUtils:
    @staticmethod
    def make_packet(seq_num, ack_num, flags, payload=b''):
        """Cria um pacote binário: Header + Payload"""
        header = struct.pack(HEADER_FORMAT, seq_num, ack_num, flags)
        return header + payload

    @staticmethod
    def parse_packet(data):
        """Separa Header e Payload"""
        if len(data) < HEADER_SIZE:
            return None, None, None, None
        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        seq_num, ack_num, flags = struct.unpack(HEADER_FORMAT, header)
        return seq_num, ack_num, flags, payload

class CryptoHandler:
    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)