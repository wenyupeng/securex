import socket
from .message import Message
import struct

# Helper functions for sending and receiving framed messages over a socket
def recv_exact(conn: socket.socket, n: int) -> bytes:
    chunks, remaining = [], n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError("Socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def recv_frame(conn: socket.socket):
    header = recv_exact(conn, Message.HEADER_SIZE)
    msg_type, length = struct.unpack(Message.HEADER_FORMAT, header)
    payload = recv_exact(conn, length)
    return msg_type, payload

def send_frame(conn: socket.socket, msg_type: int, payload: bytes):
    frame = Message.encode(msg_type, payload)
    conn.sendall(frame)
