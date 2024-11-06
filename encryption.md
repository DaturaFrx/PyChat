import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import json
import uuid
import base64
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
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
        
        # Configure dark theme
        style = ttk.Style()
        style.configure("Soft.TFrame", background='#3a3a3a')
        style.configure("Soft.TLabel", background='#3a3a3a', foreground='#e0e0e0')
        style.configure("Soft.TEntry", fieldbackground='#4a4a4a', foreground='#000000')
        style.configure("Soft.TButton", background='#4a4a4a', foreground='#000000')
        
        # Connection state
        self.connection_state = "disconnected"  # states: disconnected, pending, connected
        self.pending_connections = {}  # Store pending connection requests
        self.active_connections = {}  # Store active connections
        
        # Generate unique ID for this instance
        self.my_id = str(uuid.uuid4())[:8]
        
        # Network setup
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', 0))  # Bind to random available port
            self.port = self.socket.getsockname()[1]
        except socket.error as e:
            messagebox.showerror("Network Error", f"Could not initialize network: {str(e)}")
            return

        # Generate RSA key pair for this instance
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Create connection string
        self.connection_string = self.create_connection_string()
        
        # Create shared secret key for encryption/decryption
        self.shared_key = None
        
        # UI Components
        self.setup_ui()
        
        # Start listening for messages
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def create_connection_string(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        data = f"{self.my_id}:{self.port}:{base64.b64encode(public_key_pem).decode()}"
        return base64.b64encode(data.encode()).decode()

    def decode_connection_string(self, connection_string):
        try:
            decoded = base64.b64decode(connection_string.encode()).decode()
            peer_id, port, peer_public_key_b64 = decoded.split(':')
            peer_public_key_pem = base64.b64decode(peer_public_key_b64.encode())
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem,
                backend=default_backend()
            )
            return peer_id, int(port), peer_public_key
        except:
            raise ValueError("Invalid connection string")

    # (rest of the methods remain the same as in the previous artifact)
    # ...

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

        # Status label
        self.status_var = tk.StringVar(value="Status: Disconnected")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, style="Soft.TLabel")
        self.status_label.pack(fill=tk.X, pady=5)

        # Disconnect button
        self.disconnect_btn = ttk.Button(main_frame, text="Disconnect", command=self.disconnect, style="Soft.TButton")
        self.disconnect_btn.pack(pady=5)

        # Update UI state
        self.update_ui_state()

    def encrypt_data(self, data):
        """Encrypt data using shared secret key"""
        if not self.shared_key:
            raise ValueError("No shared key available for encryption")

        # Convert data to JSON string and encode
        json_data = json.dumps(data).encode()
        
        # Generate a random nonce
        nonce = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.shared_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(json_data) + encryptor.finalize()
        
        # Combine nonce, tag and ciphertext
        return base64.b64encode(nonce + encryptor.tag + ciphertext)

    def decrypt_data(self, encrypted_data):
        """Decrypt data using shared secret key"""
        if not self.shared_key:
            raise ValueError("No shared key available for decryption")

        # Decode from base64
        raw_data = base64.b64decode(encrypted_data)
        
        # Extract nonce, tag and ciphertext
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.shared_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Parse JSON
        return json.loads(decrypted_data.decode())

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PChatApp(root)
    root.mainloop()