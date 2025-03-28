import socket
import threading
import time
import os
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from zeroconf import ServiceInfo, Zeroconf
import getpass

class SecureP2PClient:
    def __init__(self, username, storage_path="./files", port=5000):
        self.username = username
        self.storage_path = storage_path
        self.port = port
        self.contacts = {}  # {username: (address, port, public_key)}
        self.available_files = {}  # {filename: file_hash}
        self.file_sources = {}  # {file_hash: [username1, username2, ...]}
        self.session_keys = {}  # {username: session_key}
        
        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)
        os.makedirs(f"{storage_path}/shared", exist_ok=True)
        os.makedirs(f"{storage_path}/received", exist_ok=True)
        os.makedirs(f"{storage_path}/private", exist_ok=True)
        
        # Generate or load keys
        self.load_or_generate_keys()
        
        # Start server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', port))
        self.server_socket.listen(5)
        
        # Start mDNS service
        self.register_mdns_service()
        
        # Start listening for connections
        threading.Thread(target=self.listen_for_connections, daemon=True).start()
        
        # Start mDNS discovery
        threading.Thread(target=self.discover_peers, daemon=True).start()
        
        # Scan and index shared files
        self.index_shared_files()
        
        print(f"P2P Client for {username} started on port {port}")

    def load_or_generate_keys(self):
        key_path = f"{self.storage_path}/private/{self.username}_key.pem"
        
        if os.path.exists(key_path):
            # Load existing key
            with open(key_path, "rb") as key_file:
                password = getpass.getpass("Enter password to decrypt your private key: ").encode()
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                    backend=default_backend()
                )
        else:
            # Generate new key pair
            password = getpass.getpass("Create a password to encrypt your private key: ").encode()
            confirm_password = getpass.getpass("Confirm password: ").encode()
            
            if password != confirm_password:
                raise ValueError("Passwords do not match!")
                
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save the private key
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
            
            with open(key_path, "wb") as key_file:
                key_file.write(pem)
        
        # Extract public key
        self.public_key = self.private_key.public_key()
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(f"{self.storage_path}/public_{self.username}_key.pem", "wb") as pub_key_file:
            pub_key_file.write(public_pem)

    def register_mdns_service(self):
        self.zeroconf = Zeroconf()
        self.service_info = ServiceInfo(
            "_securep2p._tcp.local.",
            f"{self.username}._securep2p._tcp.local.",
            addresses=[socket.inet_aton("127.0.0.1")],
            port=self.port,
            properties={
                'username': self.username,
                'pubkey': base64.b64encode(self.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8')
            }
        )
        self.zeroconf.register_service(self.service_info)
        print(f"mDNS service registered: {self.username}._securep2p._tcp.local.")

    def discover_peers(self):
        # This is a simplified version - in practice, you'd use a proper mDNS library to discover services
        # This function would periodically scan for peers and update self.contacts
        pass

    def listen_for_connections(self):
        while True:
            client_socket, address = self.server_socket.accept()
            threading.Thread(target=self.handle_connection, args=(client_socket, address), daemon=True).start()

    def handle_connection(self, client_socket, address):
        try:
            # Read the message type
            message = self.receive_message(client_socket)
            message_type = message.get('type')
            sender = message.get('sender')
            
            if message_type == 'handshake':
                self.handle_handshake(client_socket, message)
            elif message_type == 'file_list_request':
                self.handle_file_list_request(client_socket, sender)
            elif message_type == 'file_request':
                self.handle_file_request(client_socket, message)
            elif message_type == 'file_transfer':
                self.handle_file_transfer(client_socket, message)
            elif message_type == 'key_rotation':
                self.handle_key_rotation(client_socket, message)
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            client_socket.close()

    def send_message(self, socket, message, encrypt_for=None):
        data = json.dumps(message).encode('utf-8')
        
        if encrypt_for and encrypt_for in self.session_keys:
            # Encrypt with session key
            session_key = self.session_keys[encrypt_for]
            iv = os.urandom(16)
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Sign the encrypted data
            signature = self.private_key.sign(
                encrypted_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            message = {
                "encrypted": True,
                "sender": self.username,
                "iv": base64.b64encode(iv).decode('utf-8'),
                "data": base64.b64encode(encrypted_data).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8')
            }
            data = json.dumps(message).encode('utf-8')
        
        # Send the length first, then the data
        socket.sendall(len(data).to_bytes(4, byteorder='big'))
        socket.sendall(data)

    def receive_message(self, socket):
        # Read message length
        length_bytes = socket.recv(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Read the message
        data = b''
        while len(data) < length:
            chunk = socket.recv(min(4096, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while receiving message")
            data += chunk
        
        message = json.loads(data.decode('utf-8'))
        
        # Check if the message is encrypted
        if message.get('encrypted', False):
            sender = message.get('sender')
            if sender not in self.session_keys:
                raise ValueError(f"No session key for {sender}")
            
            session_key = self.session_keys[sender]
            iv = base64.b64decode(message['iv'])
            encrypted_data = base64.b64decode(message['data'])
            signature = base64.b64decode(message['signature'])
            
            # Verify the signature
            sender_public_key = self.contacts[sender][2]
            try:
                sender_public_key.verify(
                    signature,
                    encrypted_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                raise ValueError("Signature verification failed")
            
            # Decrypt the data
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = sym_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return json.loads(data.decode('utf-8'))
        
        return message

    def handle_handshake(self, client_socket, message):
        sender = message['sender']
        sender_public_key_bytes = base64.b64decode(message['public_key'])
        sender_public_key = serialization.load_der_public_key(
            sender_public_key_bytes,
            backend=default_backend()
        )
        
        # Generate a session key
        session_key = os.urandom(32)  # 256-bit key for AES-256
        
        # Encrypt the session key with the sender's public key
        encrypted_session_key = sender_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Store the contact information
        self.contacts[sender] = (message['address'], message['port'], sender_public_key)
        
        # Store the session key
        self.session_keys[sender] = session_key
        
        # Send response
        response = {
            'type': 'handshake_response',
            'sender': self.username,
            'public_key': base64.b64encode(self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8'),
            'session_key': base64.b64encode(encrypted_session_key).decode('utf-8')
        }
        
        self.send_message(client_socket, response)
        print(f"Handshake completed with {sender}")

    def connect_to_peer(self, username, address, port):
        if username in self.contacts:
            print(f"Already connected to {username}")
            return True
        
        try:
            # Connect to the peer
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((address, port))
            
            # Send handshake
            handshake = {
                'type': 'handshake',
                'sender': self.username,
                'address': socket.gethostbyname(socket.gethostname()),
                'port': self.port,
                'public_key': base64.b64encode(self.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8')
            }
            
            self.send_message(peer_socket, handshake)
            
            # Receive response
            response = self.receive_message(peer_socket)
            
            if response['type'] == 'handshake_response':
                peer_public_key_bytes = base64.b64decode(response['public_key'])
                peer_public_key = serialization.load_der_public_key(
                    peer_public_key_bytes,
                    backend=default_backend()
                )
                
                # Decrypt the session key
                encrypted_session_key = base64.b64decode(response['session_key'])
                session_key = self.private_key.decrypt(
                    encrypted_session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Store the contact information
                self.contacts[username] = (address, port, peer_public_key)
                
                # Store the session key
                self.session_keys[username] = session_key
                
                print(f"Connected to {username}")
                return True
            
            return False
        except Exception as e:
            print(f"Error connecting to peer {username}: {e}")
            return False
        finally:
            peer_socket.close()

    def index_shared_files(self):
        shared_dir = f"{self.storage_path}/shared"
        for filename in os.listdir(shared_dir):
            file_path = os.path.join(shared_dir, filename)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                self.available_files[filename] = file_hash
                if file_hash not in self.file_sources:
                    self.file_sources[file_hash] = []
                if self.username not in self.file_sources[file_hash]:
                    self.file_sources[file_hash].append(self.username)
        
        print(f"Indexed {len(self.available_files)} shared files")

    def handle_file_list_request(self, client_socket, sender):
        response = {
            'type': 'file_list_response',
            'sender': self.username,
            'files': self.available_files
        }
        
        self.send_message(client_socket, response, encrypt_for=sender)
        print(f"Sent file list to {sender}")

    def request_file_list(self, username):
        if username not in self.contacts:
            print(f"Not connected to {username}")
            return None
        
        address, port, _ = self.contacts[username]
        
        try:
            # Connect to the peer
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((address, port))
            
            # Send file list request
            request = {
                'type': 'file_list_request',
                'sender': self.username
            }
            
            self.send_message(peer_socket, request, encrypt_for=username)
            
            # Receive response
            response = self.receive_message(peer_socket)
            
            if response['type'] == 'file_list_response':
                print(f"Received file list from {username}")
                
                # Update file sources
                for filename, file_hash in response['files'].items():
                    if file_hash not in self.file_sources:
                        self.file_sources[file_hash] = []
                    if username not in self.file_sources[file_hash]:
                        self.file_sources[file_hash].append(username)
                
                return response['files']
            
            return None
        except Exception as e:
            print(f"Error requesting file list from {username}: {e}")
            return None
        finally:
            peer_socket.close()

    def handle_file_request(self, client_socket, message):
        sender = message['sender']
        filename = message['filename']
        
        if filename not in self.available_files:
            response = {
                'type': 'file_response',
                'sender': self.username,
                'filename': filename,
                'status': 'not_found'
            }
            self.send_message(client_socket, response, encrypt_for=sender)
            return
        
        # Ask for consent
        consent = input(f"{sender} is requesting file '{filename}'. Allow? (y/n): ")
        
        if consent.lower() != 'y':
            response = {
                'type': 'file_response',
                'sender': self.username,
                'filename': filename,
                'status': 'denied'
            }
            self.send_message(client_socket, response, encrypt_for=sender)
            return
        
        # Send the file
        file_path = os.path.join(self.storage_path, 'shared', filename)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        response = {
            'type': 'file_transfer',
            'sender': self.username,
            'filename': filename,
            'file_hash': file_hash,
            'file_data': base64.b64encode(file_data).decode('utf-8')
        }
        
        self.send_message(client_socket, response, encrypt_for=sender)
        print(f"File '{filename}' sent to {sender}")

    def request_file(self, username, filename):
        if username not in self.contacts:
            print(f"Not connected to {username}")
            return False
        
        address, port, _ = self.contacts[username]
        
        try:
            # Connect to the peer
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((address, port))
            
            # Send file request
            request = {
                'type': 'file_request',
                'sender': self.username,
                'filename': filename
            }
            
            self.send_message(peer_socket, request, encrypt_for=username)
            
            # Receive response
            response = self.receive_message(peer_socket)
            
            if response['type'] == 'file_response':
                if response['status'] == 'not_found':
                    print(f"File '{filename}' not found on {username}'s device")
                    return False
                elif response['status'] == 'denied':
                    print(f"{username} denied your request for file '{filename}'")
                    return False
            elif response['type'] == 'file_transfer':
                file_data = base64.b64decode(response['file_data'])
                file_hash = hashlib.sha256(file_data).hexdigest()
                
                # Verify the file hash
                if file_hash != response['file_hash']:
                    print(f"File hash mismatch for '{filename}' from {username}")
                    return False
                
                # Save the file
                save_path = os.path.join(self.storage_path, 'received', filename)
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                
                print(f"File '{filename}' received from {username} and saved to {save_path}")
                
                # Update file sources
                if file_hash not in self.file_sources:
                    self.file_sources[file_hash] = []
                if self.username not in self.file_sources[file_hash]:
                    self.file_sources[file_hash].append(self.username)
                
                return True
            
            return False
        except Exception as e:
            print(f"Error requesting file from {username}: {e}")
            return False
        finally:
            peer_socket.close()

    def handle_file_transfer(self, client_socket, message):
        sender = message['sender']
        filename = message['filename']
        file_data = base64.b64decode(message['file_data'])
        received_hash = message['file_hash']
        
        # Verify the file hash
        calculated_hash = hashlib.sha256(file_data).hexdigest()
        if calculated_hash != received_hash:
            print(f"File hash mismatch for '{filename}' from {sender}")
            return
        
        # Ask for consent
        consent = input(f"{sender} is sending file '{filename}'. Accept? (y/n): ")
        
        if consent.lower() != 'y':
            print(f"Rejected file '{filename}' from {sender}")
            return
        
        # Save the file
        save_path = os.path.join(self.storage_path, 'received', filename)
        with open(save_path, 'wb') as f:
            f.write(file_data)
        
        print(f"File '{filename}' received from {sender} and saved to {save_path}")
        
        # Update file sources
        if received_hash not in self.file_sources:
            self.file_sources[received_hash] = []
        if self.username not in self.file_sources[received_hash]:
            self.file_sources[received_hash].append(self.username)

    def rotate_key(self):
        # Generate new key pair
        password = getpass.getpass("Enter password to encrypt your new private key: ").encode()
        
        new_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        new_public_key = new_private_key.public_key()
        
        # Save the new keys
        key_path = f"{self.storage_path}/private/{self.username}_key_new.pem"
        
        pem = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        
        with open(key_path, "wb") as key_file:
            key_file.write(pem)
        
        # Notify all contacts
        for contact_name, (address, port, _) in self.contacts.items():
            try:
                # Connect to the peer
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect((address, port))
                
                # Send key rotation notification
                notification = {
                    'type': 'key_rotation',
                    'sender': self.username,
                    'new_public_key': base64.b64encode(new_public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )).decode('utf-8')
                }
                
                self.send_message(peer_socket, notification, encrypt_for=contact_name)
                
                # Receive acknowledgment
                response = self.receive_message(peer_socket)
                
                if response['type'] == 'key_rotation_ack':
                    print(f"Key rotation notification sent to {contact_name}")
                
                peer_socket.close()
            except Exception as e:
                print(f"Error notifying {contact_name} about key rotation: {e}")
        
        # Replace the old key with the new one
        os.rename(key_path, f"{self.storage_path}/private/{self.username}_key.pem")
        self.private_key = new_private_key
        self.public_key = new_public_key
        
        # Save the new public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(f"{self.storage_path}/public_{self.username}_key.pem", "wb") as pub_key_file:
            pub_key_file.write(public_pem)
        
        print("Key rotation completed successfully")

    def handle_key_rotation(self, client_socket, message):
        sender = message['sender']
        new_public_key_bytes = base64.b64decode(message['new_public_key'])
        new_public_key = serialization.load_der_public_key(
            new_public_key_bytes,
            backend=default_backend()
        )
        
        if sender in self.contacts:
            address, port, _ = self.contacts[sender]
            self.contacts[sender] = (address, port, new_public_key)
            
            # Generate a new session key
            session_key = os.urandom(32)  # 256-bit key for AES-256
            
            # Encrypt the session key with the sender's new public key
            encrypted_session_key = new_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Store the new session key
            self.session_keys[sender] = session_key
            
            # Send acknowledgment
            response = {
                'type': 'key_rotation_ack',
                'sender': self.username,
                'session_key': base64.b64encode(encrypted_session_key).decode('utf-8')
            }
            
            self.send_message(client_socket, response)
            print(f"Updated key for {sender}")

    def find_file_source(self, filename, file_hash):
        # Find all sources for a file with the given hash
        if file_hash in self.file_sources:
            sources = [source for source in self.file_sources[file_hash] if source != self.username]
            if sources:
                return sources
        return None

    def close(self):
        self.zeroconf.unregister_service(self.service_info)
        self.zeroconf.close()
        self.server_socket.close()
        print(f"P2P Client for {self.username} stopped")

# Example usage
if __name__ == "__main__":
    username = input("Enter your username: ")
    client = SecureP2PClient(username)
    
    try:
        while True:
            print("\nCommands:")
            print("1. Connect to peer")
            print("2. Request file list")
            print("3. Request file")
            print("4. List all known files")
            print("5. Share a new file")
            print("6. Rotate key")
            print("7. Exit")
            
            choice = input("Enter choice: ")
            
            if choice == '1':
                peer_username = input("Enter peer username: ")
                peer_address = input("Enter peer address: ")
                peer_port = int(input("Enter peer port: "))
                client.connect_to_peer(peer_username, peer_address, peer_port)
            elif choice == '2':
                peer_username = input("Enter peer username: ")
                files = client.request_file_list(peer_username)
                if files:
                    print(f"Files available from {peer_username}:")
                    for filename, file_hash in files.items():
                        print(f"  - {filename} ({file_hash[:8]}...)")
            elif choice == '3':
                peer_username = input("Enter peer username: ")
                filename = input("Enter filename: ")
                client.request_file(peer_username, filename)
            elif choice == '4':
                print("Known files:")
                for file_hash, sources in client.file_sources.items():
                    print(f"File hash: {file_hash[:8]}...")
                    print(f"  Sources: {', '.join(sources)}")
            elif choice == '5':
                file_path = input("Enter path to file: ")
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(client.storage_path, 'shared', filename)
                    with open(file_path, 'rb') as src, open(dest_path, 'wb') as dest:
                        dest.write(src.read())
                    client.index_shared_files()
                    print(f"File '{filename}' added to shared files")
                else:
                    print("File not found")
            elif choice == '6':
                client.rotate_key()
            elif choice == '7':
                break
    finally:
        client.close()