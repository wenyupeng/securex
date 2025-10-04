import socket
import os
from datetime import datetime
from securex.key_exchange import KeyExchange
from securex.secure_channel import SecureChannel
from securex.io_utils import recv_frame

HOST, PORT = "127.0.0.1", 65432
TYPE_DATA, TYPE_CLOSE, TYPE_FILE = 0x01, 0x02, 0x03

def handle_client(conn, addr):
    print(f"[Server] Connected: {addr}")
    server_kex = KeyExchange()

    try:
        client_pub = conn.recv(4096)
        if not client_pub:
            print(f"[Server] ❌ Client {addr} disconnected during handshake")
            return

        sever_pub = server_kex.get_public_bytes()
        conn.sendall(sever_pub)
        aes_key, hmac_key = server_kex.derive_shared_keys(client_pub)
        channel = SecureChannel(aes_key, hmac_key)
        print(f"[Server] ✅ Secure channel established for {addr}. Key: {aes_key.hex()[:32]}...")

        while True:
            try:
                frame = recv_frame(conn)
                if not frame:
                    print(f"[Server] ❌ Client {addr} closed connection")
                    break
                msg_type, payload = frame

                if msg_type == TYPE_DATA:
                    print(f"[Server:{addr}] Ciphertext: {payload.hex()}")
                    plaintext = channel.decrypt(payload).decode(errors="ignore")
                    print(f"[Server:{addr}] Decrypted: {plaintext}")

                elif msg_type == TYPE_FILE:
                    decrypted = channel.decrypt(payload)
                    filename = f"received_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    with open(filename, "wb") as f:
                        f.write(decrypted)
                    size = os.path.getsize(filename)
                    print(f"[Server:{addr}] 📁 File saved as '{filename}' ({size} bytes)")

                elif msg_type == TYPE_CLOSE:
                    print(f"[Server] 📴 Client {addr} requested close. Clearing connection info.")
                    break  

                else:
                    print(f"[Server] ⚠ Unknown message type: {msg_type}")

            except (ConnectionResetError, BrokenPipeError):
                print(f"[Server] ❌ Connection reset by {addr}")
                break
            except Exception as e:
                print(f"[Server] ❌ Error with {addr}: {e}")
                break

    finally:
        conn.close()
        print(f"[Server] Connection with {addr} closed. Waiting for new clients...\n")


def run_server():
    """
    Run the secure echo server that handles multiple clients sequentially.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening {HOST}:{PORT} ...")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    run_server()
