import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from securex.key_exchange import KeyExchange
from securex.secure_channel import SecureChannel
from securex.io_utils import send_frame

HOST, PORT = "127.0.0.1", 65432
TYPE_DATA, TYPE_CLOSE, TYPE_FILE = 0x01, 0x02, 0x03

class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        top_frame = tk.Frame(root)
        top_frame.pack(fill=tk.X, padx=10, pady=(5, 0))

        self.key_label = tk.Label(top_frame, text="[Key] 未连接", fg="blue", anchor="w", justify="left")
        self.key_label.pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.connect_button = tk.Button(top_frame, text="Connect", command=self.connect_server)
        self.connect_button.pack(side=tk.RIGHT, padx=5)

        self.stop_button = tk.Button(top_frame, text="Stop", command=self.stop_client, state="disabled")
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20, state="disabled")
        self.text_area.pack(padx=10, pady=5)

        input_frame = tk.Frame(root)
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        self.entry = tk.Entry(input_frame, width=50)
        self.entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message, state="disabled")
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.file_button = tk.Button(input_frame, text="Send File/Video", command=self.send_file, state="disabled")
        self.file_button.pack(side=tk.LEFT, padx=5)

        self.sock = None
        self.channel = None
        self.running = False

    def connect_server(self):
        if self.sock:
            messagebox.showinfo("Info", "Already connected.")
            return
        try:
            client_kex = KeyExchange()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))

            client_pub = client_kex.get_public_bytes()
            self.sock.sendall(client_pub)
            server_pub = self.sock.recv(4096)
            print("[Client] Client public key:", client_pub)
            print("[Client] Sever public key:", server_pub)

            aes_key, hmac_key = client_kex.derive_shared_keys(server_pub)
            self.channel = SecureChannel(aes_key, hmac_key)
            self.key_label.config(text=f"[Key] Shared key: {aes_key.hex()[:64]}...")

            self.running = True
            self.append_text("[Client] ✅ Connected & Secure channel established\n")

            self.stop_button.config(state="normal")
            self.send_button.config(state="normal")
            self.file_button.config(state="normal")

            threading.Thread(target=self.receive_loop, daemon=True).start()
        except Exception as e:
            self.append_text(f"[Error] {e}\n")
            self.sock = None

    def stop_client(self):
        try:
            if self.sock:
                send_frame(self.sock, TYPE_CLOSE, b"close")
                self.sock.close()
        except Exception:
            pass
        finally:
            self.sock = None
            self.channel = None
            self.running = False

            self.text_area.config(state="normal")
            self.text_area.delete(1.0, tk.END)
            self.text_area.config(state="disabled")
            self.key_label.config(text="[Key] 未连接")

            self.stop_button.config(state="disabled")
            self.send_button.config(state="disabled")
            self.file_button.config(state="disabled")

    def receive_loop(self):
        try:
            while self.running:
                header = self.sock.recv(5)
                if not header:
                    break
                frame_type = header[0]
                length = int.from_bytes(header[1:], "big")
                payload = self.sock.recv(length)

                if frame_type == TYPE_DATA:
                    self.append_text(f"[Ciphertext] {payload.hex()}\n", "purple")
                    plaintext = self.channel.decrypt(payload).decode(errors="ignore")
                    self.append_text(f"[Decrypted] {plaintext}\n", "green")

                elif frame_type == TYPE_FILE:
                    filename = "received_file"
                    with open(filename, "wb") as f:
                        decrypted = self.channel.decrypt(payload)
                        f.write(decrypted)
                    self.append_text(f"[File] Received and saved as {filename}\n", "blue")

                elif frame_type == TYPE_CLOSE:
                    self.append_text("[Server] Connection closed\n")
                    break
        except Exception as e:
            self.append_text(f"[Error] Receive loop: {e}\n")
        finally:
            self.stop_client()

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg or not self.channel:
            return
        self.append_text(f"You> {msg}\n")
        self.entry.delete(0, tk.END)

        if msg.lower() in {"quit", "exit", ":q"}:
            self.stop_client()
        else:
            ciphertext = self.channel.encrypt(msg.encode())
            send_frame(self.sock, TYPE_DATA, ciphertext)
            self.append_text(f"[Sent Ciphertext] {ciphertext.hex()}\n", "gray")

    def send_file(self):
        if not self.channel:
            messagebox.showwarning("Warning", "Not connected!")
            return
        file_path = filedialog.askopenfilename(title="Select File or Video")
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            encrypted = self.channel.encrypt(data)
            send_frame(self.sock, TYPE_FILE, encrypted)
            self.append_text(f"[File Sent] {file_path}\n", "orange")
        except Exception as e:
            self.append_text(f"[Error Sending File] {e}\n")

    def append_text(self, text, color=None):
        self.text_area.config(state="normal")
        if color:
            self.text_area.tag_config(color, foreground=color)
            self.text_area.insert(tk.END, text, color)
        else:
            self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.config(state="disabled")

def run_client():
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()

if __name__ == "__main__":
    run_client()
