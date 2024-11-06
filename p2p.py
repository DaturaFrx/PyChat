import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import json
import uuid
import base64
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

CONFIG_FILE = "user_config.json"

def load_username():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            return config.get("username", "User")
    else:
        username = "UserName"
        save_username(username)
        return username

def save_username(username):
    with open(CONFIG_FILE, "w") as file:
        json.dump({"username": username}, file)

# Load username at start
username = load_username()

class P2PChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyChat")
        self.root.configure(bg='#2b2b2b')
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self.shared_key = None
        
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()
        
        style = ttk.Style()
        style.configure("Soft.TFrame", background='#3a3a3a')
        style.configure("Soft.TLabel", background='#3a3a3a', foreground='#e0e0e0')
        style.configure("Soft.TEntry", fieldbackground='#4a4a4a', foreground='#000000')
        style.configure("Soft.TButton", background='#4a4a4a', foreground='#000000')
        
        # Connection state
        self.connection_state = "disconnected"  # states: disconnected, pending, connected
        self.pending_connections = {}  # Store pending connection requests
        self.active_connections = {}  # Store active connections
        
        self.my_id = str(uuid.uuid4())[:8]
        
        # Network setup
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', 0))  # Bind to random available port
            self.port = self.socket.getsockname()[1]
            
            # Create connection string
            self.connection_string = self.create_connection_string()
        except socket.error as e:
            messagebox.showerror("Network Error", f"Could not initialize network: {str(e)}")
            return
        
        self.setup_ui()
        
        # Start listening for messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def create_connection_string(self):
        data = f"{self.my_id}:{self.port}:{self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1)}"
        return base64.b64encode(data.encode()).decode()

    def decode_connection_string(self, connection_string):
        try:
            decoded = base64.b64decode(connection_string.encode()).decode()
            peer_id, port, peer_public_key = decoded.split(':')
            return peer_id, int(port), peer_public_key
        except:
            raise ValueError("Invalid connection string")

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, style="Soft.TFrame")
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Connection frame
        conn_frame = ttk.Frame(main_frame, style="Soft.TFrame")
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Your connection string
        id_frame = ttk.Frame(conn_frame, style="Soft.TFrame")
        id_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(id_frame, text="Your Connection String:", style="Soft.TLabel").pack(side=tk.LEFT)
        self.conn_string_var = tk.StringVar(value=self.connection_string)
        conn_entry = ttk.Entry(id_frame, textvariable=self.conn_string_var, style="Soft.TEntry", width=40)
        conn_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(id_frame, text="Copy", command=self.copy_connection_string, style="Soft.TButton").pack(side=tk.LEFT)
        
        # Peer connection string input
        peer_frame = ttk.Frame(conn_frame, style="Soft.TFrame")
        peer_frame.pack(fill=tk.X, pady=5)
        ttk.Label(peer_frame, text="Peer Connection String:", style="Soft.TLabel").pack(side=tk.LEFT)
        self.peer_conn_string_var = tk.StringVar()
        self.peer_conn_entry = ttk.Entry(peer_frame, textvariable=self.peer_conn_string_var, style="Soft.TEntry", width=40)
        self.peer_conn_entry.pack(side=tk.LEFT, padx=5)
        self.connect_btn = ttk.Button(peer_frame, text="Connect", command=self.initiate_connection, style="Soft.TButton")
        self.connect_btn.pack(side=tk.LEFT)
        
        # Disconnect button
        self.disconnect_btn = ttk.Button(conn_frame, text="Disconnect", command=self.disconnect, style="Soft.TButton")
        self.disconnect_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Status: Disconnected")
        self.status_label = ttk.Label(conn_frame, textvariable=self.status_var, style="Soft.TLabel")
        self.status_label.pack(fill=tk.X, pady=5)
        
        # Chat display
        self.chat_display = tk.Text(main_frame, height=15, bg='#3b3b3b', fg='#ffffff')
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.chat_display.config(state=tk.DISABLED)
        
        # Message input and send
        input_frame = ttk.Frame(main_frame, style="Soft.TFrame")
        input_frame.pack(fill=tk.X)
        
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var, style="Soft.TEntry")
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.send_btn = ttk.Button(input_frame, text="Send", command=self.send_message, style="Soft.TButton")
        self.send_btn.pack(side=tk.RIGHT)
        
        # Bind Enter key to send message
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        # Update UI state
        self.update_ui_state()

    def copy_connection_string(self):
        """Copy connection string to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.connection_string)
        messagebox.showinfo("Success", "Connection string copied to clipboard!")

    def update_ui_state(self):
        """Update UI elements based on connection state"""
        if self.connection_state == "disconnected":
            self.status_var.set("Status: Disconnected")
            self.connect_btn.config(state=tk.NORMAL)
            self.send_btn.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.DISABLED)
        elif self.connection_state == "pending":
            self.status_var.set("Status: Connection Pending...")
            self.connect_btn.config(state=tk.DISABLED)
            self.send_btn.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.DISABLED)
        elif self.connection_state == "connected":
            self.status_var.set("Status: Connected")
            self.connect_btn.config(state=tk.DISABLED)
            self.send_btn.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)

    def initiate_connection(self):
        try:
            peer_conn_string = self.peer_conn_string_var.get()
            peer_id, peer_port, peer_public_key = self.decode_connection_string(peer_conn_string)

            # Generate shared secret key using HKDF
            peer_public_key_obj = serialization.load_pem_public_key(peer_public_key.encode(), backend=default_backend())
            shared_secret = self.private_key.exchange(peer_public_key_obj)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
                backend=default_backend()
            ).derive(shared_secret)

            data = {
                'type': 'connection_request',
                'sender_id': self.my_id,
                'sender_port': self.port,
                'connection_string': self.connection_string,
                'nonce': secrets.token_hex(16)
            }
            encrypted_data = self.encrypt_data(data)
            self.socket.sendto(encrypted_data, ('localhost', peer_port))

            self.connection_state = "pending"
            self.update_ui_state()
            self.add_message(f"Encrypted connection request sent to {peer_id}")

        except ValueError:
            messagebox.showerror("Error", "Invalid connection string")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")

    def handle_connection_request(self, data, addr):
        try:
            # Decrypt the received data
            decrypted_data = self.decrypt_data(data)
            sender_id = decrypted_data['sender_id']
            sender_port = decrypted_data['sender_port']
            peer_conn_string = decrypted_data['connection_string']
            nonce = decrypted_data['nonce']

            # Decode the connection string to get the peer's public key
            _, _, peer_public_key = self.decode_connection_string(peer_conn_string)
            peer_public_key_obj = serialization.load_pem_public_key(peer_public_key.encode(), backend=default_backend())

            # Generate shared secret key using HKDF
            shared_secret = self.private_key.exchange(peer_public_key_obj)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
                backend=default_backend()
            ).derive(shared_secret)

            if messagebox.askyesno("Connection Request", f"Accept encrypted connection request from {username}?"):
                # Accept connection
                response_data = {
                    'type': 'connection_accepted',
                    'sender_id': self.my_id,
                    'sender_port': self.port,
                    'connection_string': self.connection_string,
                    'nonce': secrets.token_hex(16)
                }
                encrypted_response = self.encrypt_data(response_data)
                self.socket.sendto(encrypted_response, ('localhost', sender_port))

                # Store connection
                self.active_connections[sender_id] = (sender_port, peer_public_key_obj)
                self.connection_state = "connected"
                self.update_ui_state()
                self.add_message(f"Encrypted connection established with {username}")
            else:
                # Reject connection
                response_data = {
                    'type': 'connection_rejected',
                    'sender_id': self.my_id,
                    'nonce': secrets.token_hex(16)
                }
                encrypted_response = self.encrypt_data(response_data)
                self.socket.sendto(encrypted_response, ('localhost', sender_port))

        except Exception as e:
            messagebox.showerror("Error", f"Error handling connection request: {str(e)}")

    def handle_connection_response(self, data):
        try:
            # Decrypt the received data
            decrypted_data = self.decrypt_data(data)

            if decrypted_data['type'] == 'connection_accepted':
                sender_id = decrypted_data['sender_id']
                sender_port = decrypted_data['sender_port']
                peer_conn_string = decrypted_data['connection_string']
                nonce = decrypted_data['nonce']

                # Decode the connection string to get the peer's public key
                _, _, peer_public_key = self.decode_connection_string(peer_conn_string)
                peer_public_key_obj = serialization.load_pem_public_key(peer_public_key.encode(), backend=default_backend())

                # Generate shared secret key using HKDF
                shared_secret = self.private_key.exchange(peer_public_key_obj)
                self.shared_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=None,
                    backend=default_backend()
                ).derive(shared_secret)

                self.active_connections[sender_id] = (sender_port, peer_public_key_obj)
                self.connection_state = "connected"
                self.update_ui_state()
                self.add_message(f"Encrypted connection established with {username}")
            elif decrypted_data['type'] == 'connection_rejected':
                sender_id = decrypted_data['sender_id']
                nonce = decrypted_data['nonce']
                self.connection_state = "disconnected"
                self.update_ui_state()
                self.add_message(f"Encrypted connection rejected by {sender_id}")

        except Exception as e:
            messagebox.showerror("Error", f"Error handling connection response: {str(e)}")

    def send_message(self):
        """Send encrypted chat message to connected peer"""
        message = self.message_var.get()
        if message and self.connection_state == "connected":
            try:
                for peer_id, (peer_port, peer_public_key) in self.active_connections.items():
                    data = {
                        'type': 'chat_message',
                        'sender_id': self.my_id,
                        'message': message,
                        'nonce': secrets.token_hex(16)
                    }
                    encrypted_data = self.encrypt_data(data, peer_public_key)
                    self.socket.sendto(encrypted_data, ('localhost', peer_port))
                self.add_message(f"You: {message}")
                self.message_var.set("")
            except Exception as e:
                messagebox.showerror("Error", f"Error sending encrypted message: {str(e)}")

    def receive_messages(self):
        """Handle incoming encrypted messages"""
        while True:
            try:
                data, addr = self.socket.recvfrom(1024)
                decrypted_data = self.decrypt_data(data)

                if decrypted_data['type'] == 'connection_request':
                    self.root.after(0, self.handle_connection_request, data, addr)
                elif decrypted_data['type'] in ['connection_accepted', 'connection_rejected']:
                    self.root.after(0, self.handle_connection_response, data)
                elif decrypted_data['type'] == 'chat_message':
                    sender_id = decrypted_data['sender_id']
                    message = decrypted_data['message']
                    self.root.after(0, self.add_message, f"{sender_id}: {message}")
            except Exception as e:
                print(f"Error receiving encrypted message: {str(e)}")

    def encrypt_data(self, data, peer_public_key=None):
        """Encrypt data using shared secret key or peer's public key"""
        if not self.shared_key and not peer_public_key:
            raise ValueError("No shared key or peer public key available for encryption")

        nonce = data.get('nonce', secrets.token_hex(16))
        aad = json.dumps(data).encode()
        cipher = Cipher(
            algorithms.ChaCha20(self.shared_key or peer_public_key.encrypt(self.shared_key, padding=OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
            modes.ChaCha20Poly1305(nonce.encode()),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(aad) + encryptor.finalize()
        return ciphertext

    def decrypt_data(self, data):
        """Decrypt data using shared secret key"""
        if not self.shared_key:
            raise ValueError("No shared key available for decryption")

        nonce = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(
            algorithms.ChaCha20(self.shared_key),
            modes.ChaCha20Poly1305(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(ciphertext)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(plaintext.decode())

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PChatApp(root)
    root.mainloop()