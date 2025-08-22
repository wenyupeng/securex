import socket
from securex.key_exchange import KeyExchange
from securex.secure_channel import SecureChannel
from securex.io_utils import recv_frame

HOST, PORT = "127.0.0.1", 65432
TYPE_DATA, TYPE_CLOSE = 0x01, 0x02

def run_server():
    server_kex = KeyExchange()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Server] Listening {HOST}:{PORT} ...")

        conn, addr = s.accept()
        with conn:
            print("[Server] Connected:", addr)

            client_pub = conn.recv(4096)
            conn.sendall(server_kex.get_public_bytes())

            key = server_kex.derive_shared_key(client_pub)
            channel = SecureChannel(key)
            print("[Server] Secure channel established ✅")

            while True:
                try:
                    msg_type, payload = recv_frame(conn)
                except EOFError:
                    print("[Server] Client disconnected")
                    break

                if msg_type == TYPE_DATA:
                    plaintext = channel.decrypt(payload)
                    print("[Server] Received:", plaintext.decode())
                elif msg_type == TYPE_CLOSE:
                    print("[Server] Close request")
                    break

if __name__ == "__main__":
    run_server()
