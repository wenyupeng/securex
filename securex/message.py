import struct

# Message Types
class Message:
    HEADER_FORMAT = "!BI"  # type (1B), length (4B)
    HEADER_SIZE = 5

    @staticmethod
    def encode(msg_type: int, payload: bytes) -> bytes:
        header = struct.pack(Message.HEADER_FORMAT, msg_type, len(payload))
        return header + payload

    @staticmethod
    def decode(data: bytes):
        msg_type, length = struct.unpack(Message.HEADER_FORMAT, data[:Message.HEADER_SIZE])
        payload = data[Message.HEADER_SIZE:Message.HEADER_SIZE+length]
        return msg_type, payload
