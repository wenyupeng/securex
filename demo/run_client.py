import socket
from securex.key_exchange import KeyExchange
from securex.secure_channel import SecureChannel
from securex.io_utils import send_frame

HOST, PORT = "127.0.0.1", 65432
TYPE_DATA, TYPE_CLOSE = 0x01, 0x02

def run_client():
    client_kex = KeyExchange()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        s.sendall(client_kex.get_public_bytes())
        server_pub = s.recv(4096)

        key = client_kex.derive_shared_key(server_pub)
        channel = SecureChannel(key)
        print("[Client] Secure channel established ✅")

        while True:
            msg = input("You> ")
            if msg.lower() in {"quit", "exit", ":q"}:
                send_frame(s, TYPE_CLOSE, b"close")
                break
            ciphertext = channel.encrypt(msg.encode())
            send_frame(s, TYPE_DATA, ciphertext)

if __name__ == "__main__":
    run_client()
