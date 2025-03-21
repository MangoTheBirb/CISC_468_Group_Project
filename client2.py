import socket
import threading
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Configuration
SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "ClientB._p2pfileshare._tcp.local."
PORT = 5001

# Dictionary to store peer keys
peer_keys = {}

SHARED_FILES_DIR = "shared_files"
if not os.path.exists(SHARED_FILES_DIR):
    os.makedirs(SHARED_FILES_DIR)

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key to send over the network
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize public key received from the network
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

# Get the local IP address
def get_local_ip():
    try:
        # Create a temporary socket to get the local IP address
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))  # Google's public DNS server
        local_ip = temp_sock.getsockname()[0]
        temp_sock.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return "127.0.0.1"  # Fallback to localhost

def get_shared_files():
    """Get list of files available for sharing"""
    try:
        return os.listdir(SHARED_FILES_DIR)
    except Exception as e:
        print(f"Error getting shared files: {e}")
        return []

def send_file(conn, filename):
    """Send a file to peer"""
    filepath = os.path.join(SHARED_FILES_DIR, filename)
    try:
        # Wait for receiver to be ready
        if conn.recv(1024) != b"READY_TO_RECEIVE":
            raise Exception("Receiver not ready")
            
        # Send file size
        with open(filepath, 'rb') as f:
            data = f.read()
            conn.sendall(str(len(data)).encode() + b'\n')
            
        # Wait for size acknowledgment
        if conn.recv(1024) != b"SIZE_RECEIVED":
            raise Exception("Size not acknowledged")
            
        # Send file data
        conn.sendall(data)
        
        # Wait for completion confirmation
        if conn.recv(1024) != b"FILE_RECEIVED":
            raise Exception("File receipt not confirmed")
            
        print(f"Sent file {filename}")
    except Exception as e:
        print(f"Error sending file {filename}: {e}")
        conn.sendall(b'0\n')

def receive_file(conn, filename):
    """Receive a file from peer"""
    filepath = os.path.join(SHARED_FILES_DIR, filename)
    try:
        # Wait for start marker
        conn.sendall(b"READY_TO_RECEIVE")
        
        # Get file size
        size = int(conn.recv(1024).decode().strip())
        if size == 0:
            print(f"Error receiving file {filename}")
            return
        
        # Acknowledge size receipt
        conn.sendall(b"SIZE_RECEIVED")
        
        # Receive file data
        data = b''
        while len(data) < size:
            packet = conn.recv(min(size - len(data), 4096))
            if not packet:
                break
            data += packet

        # Save file
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"Received file {filename}")
        
        # Confirm receipt
        conn.sendall(b"FILE_RECEIVED")
    except Exception as e:
        print(f"Error receiving file {filename}: {e}")

# Register the service using mDNS
def register_service():
    local_ip = get_local_ip()
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(local_ip)],
        port=PORT,
        properties={"description": "Client A"},
    )
    zeroconf = Zeroconf()
    zeroconf.register_service(info)
    print(f"Client A registered as {SERVICE_NAME} at {local_ip}:{PORT}")
    return zeroconf

def authenticate_connection(conn, private_key, public_key):
    """Authenticate connection with peer"""
    try:
        # Exchange public keys
        conn.sendall(serialize_public_key(public_key))
        peer_public_key_bytes = conn.recv(1024)
        peer_public_key = deserialize_public_key(peer_public_key_bytes)

        # Verify identity by signing a challenge
        challenge = b"authentication challenge"
        signature = private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        conn.sendall(signature)
        peer_signature = conn.recv(256)
        
        peer_public_key.verify(
            peer_signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False

def update_peer_key(addr, new_public_key):
    """Update stored public key for a peer"""
    # You'll need to maintain a dictionary of peer keys
    peer_keys[addr] = new_public_key

# Update the handle_client function to handle key changes
def handle_client(conn, addr, private_key, public_key):
    print(f"Connected to {addr}")
    try:
        # Authenticate connection
        if not authenticate_connection(conn, private_key, public_key):
            conn.close()
            return

        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
                
            if data == "KEY_CHANGE":
                # Receive new public key
                new_public_key_bytes = conn.recv(1024)
                new_public_key = deserialize_public_key(new_public_key_bytes)
                
                # Receive signature
                signature = conn.recv(256)
                
                try:
                    # Verify signature using old public key
                    public_key.verify(
                        signature,
                        serialize_public_key(new_public_key),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    
                    # Update stored public key for this peer
                    update_peer_key(addr, new_public_key)
                    
                    # Acknowledge key change
                    conn.sendall(b"KEY_UPDATED")
                    print(f"Updated public key for peer {addr}")
                    
                except Exception as e:
                    print(f"Failed to verify new key from {addr}: {e}")
                    conn.sendall(b"KEY_REJECTED")
                    
            if data == "LIST_FILES":
                files = get_shared_files()
                conn.sendall('\n'.join(files).encode())
                
            elif data.startswith("REQUEST_FILE:"):
                filename = data.split(':', 1)[1]
                consent = input(f"\nPeer {addr} requests file '{filename}'. Allow? (yes/no): ")
                if consent.lower() == 'yes':
                    print(f"Sending file {filename} to {addr}")
                    send_file(conn, filename)
                else:
                    print(f"Denied file request for {filename}")
                    conn.sendall(b'0\n')
                    
            elif data.startswith("SEND_FILE:"):
                filename = data.split(':', 1)[1]
                consent = input(f"\nPeer {addr} wants to send file '{filename}'. Accept? (yes/no): ")
                if consent.lower() == 'yes':
                    print(f"Receiving file {filename} from {addr}")
                    receive_file(conn, filename)
                else:
                    print(f"Rejected file {filename} from {addr}")
                    
            else:
                print(f"Received from {addr}: {data}")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

# Start server
def start_server(private_key, public_key):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))  # Bind to all available interfaces
    server.listen()
    print(f"Server started on port {PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr, private_key, public_key)).start()

# Listener to handle discovered services
class MyListener(ServiceListener):
    def __init__(self, local_ip, service_name, private_key, public_key):
        self.local_ip = local_ip
        self.service_name = service_name
        self.private_key = private_key
        self.public_key = public_key
        self.known_peers = []  # Change to list instead of dictionary

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            peer_ip = socket.inet_ntoa(info.addresses[0])
            peer_port = info.port
            # Ignore self-discovery
            if peer_ip != self.local_ip or name != self.service_name:
                print(f"Discovered service: {name}")
                print(f"Address: {peer_ip}")
                print(f"Port: {peer_port}")
                print(f"Properties: {info.properties}")
                # Connect to the discovered peer
                threading.Thread(target=self.connect_to_peer, args=(peer_ip, peer_port)).start()

    def connect_to_peer(self, peer_ip, peer_port):
        try:
            conn = socket.create_connection((peer_ip, peer_port))
            # Add peer to known_peers if not already present
            peer = (peer_ip, peer_port)
            if peer not in self.known_peers:
                self.known_peers.append(peer)
            
            # Create a new thread for handling the connection
            threading.Thread(target=handle_client, 
                           args=(conn, (peer_ip, peer_port), self.private_key, self.public_key)).start()
        except Exception as e:
            print(f"Failed to connect to peer {peer_ip}:{peer_port}: {e}")

    def authenticate_connection(self, conn, private_key, public_key):
        """Authenticate connection with peer"""
        try:
            # Add message markers for proper framing
            conn.sendall(b"BEGIN_KEY\n")
            conn.sendall(serialize_public_key(public_key))
            conn.sendall(b"END_KEY\n")
            
            # Read peer's public key
            data = b""
            while b"BEGIN_KEY\n" not in data:
                data += conn.recv(1024)
            data = data.split(b"BEGIN_KEY\n")[1]
            
            while b"END_KEY\n" not in data:
                data += conn.recv(1024)
            peer_public_key_bytes = data.split(b"END_KEY\n")[0]
            
            peer_public_key = deserialize_public_key(peer_public_key_bytes)
            print(f"Received peer public key")

            # Continue with challenge verification
            challenge = b"authentication challenge"
            signature = private_key.sign(
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            conn.sendall(b"BEGIN_SIG\n")
            conn.sendall(signature)
            conn.sendall(b"END_SIG\n")
            
            # Read peer's signature
            data = b""
            while b"BEGIN_SIG\n" not in data:
                data += conn.recv(1024)
            data = data.split(b"BEGIN_SIG\n")[1]
            
            while b"END_SIG\n" not in data:
                data += conn.recv(1024)
            peer_signature = data.split(b"END_SIG\n")[0]

            peer_public_key.verify(
                peer_signature,
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    def request_file_from_peer(self, peer_ip, peer_port, filename):
        """Request a file from a peer"""
        try:
            # Create new connection for file transfer
            conn = socket.create_connection((peer_ip, peer_port))
            
            # Authenticate first
            if not authenticate_connection(conn, self.private_key, self.public_key):
                conn.close()
                return

            # Send file request
            conn.sendall(f"REQUEST_FILE:{filename}".encode())
            
            # Receive file
            receive_file(conn, filename)
            conn.close()
        except Exception as e:
            print(f"Failed to request file from peer {peer_ip}:{peer_port}: {e}")

    def send_file_to_peer(self, peer_ip, peer_port, filename):
        """Send a file to a peer"""
        try:
            # Create new connection for file transfer
            conn = socket.create_connection((peer_ip, peer_port))
            
            # Authenticate first
            if not authenticate_connection(conn, self.private_key, self.public_key):
                conn.close()
                return

            # Send file request
            conn.sendall(f"SEND_FILE:{filename}".encode())
            
            # Send file
            send_file(conn, filename)
            conn.close()
        except Exception as e:
            print(f"Failed to send file to peer {peer_ip}:{peer_port}: {e}")

    def request_peer_files(self, peer_ip, peer_port):
        """Request list of files from a peer"""
        try:
            # Create new connection for file list request
            conn = socket.create_connection((peer_ip, peer_port))
            
            # Authenticate first
            if not authenticate_connection(conn, self.private_key, self.public_key):
                conn.close()
                return []

            # Request file list
            conn.sendall("LIST_FILES".encode())
            
            # Receive file list
            file_list = conn.recv(1024).decode().split('\n')
            conn.close()
            return file_list
        except Exception as e:
            print(f"Failed to get file list from peer {peer_ip}:{peer_port}: {e}")
            return []

    def migrate_to_new_key(self):
        """Migrate to a new key pair and notify peers"""
        try:
            # Generate new key pair
            new_private_key, new_public_key = generate_key_pair()
            
            # Store old keys temporarily for verification
            old_private_key = self.private_key
            old_public_key = self.public_key
            
            # Update keys
            self.private_key = new_private_key
            self.public_key = new_public_key
            
            # Sign the new public key with the old private key for verification
            signature = old_private_key.sign(
                serialize_public_key(new_public_key),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Notify all known peers
            self.notify_peers_of_key_change(new_public_key, signature)
            
            print("Successfully migrated to new key pair")
            return True
        except Exception as e:
            print(f"Failed to migrate to new key: {e}")
            return False

    def notify_peers_of_key_change(self, new_public_key, signature):
        """Notify all known peers about the key change"""
        for peer in self.known_peers:
            try:
                conn = socket.create_connection(peer)
                
                # Send key change notification
                conn.sendall(b"KEY_CHANGE")
                
                # Send new public key
                conn.sendall(serialize_public_key(new_public_key))
                
                # Send signature of new key signed with old key
                conn.sendall(signature)
                
                # Wait for acknowledgment
                response = conn.recv(1024).decode()
                if response == "KEY_UPDATED":
                    print(f"Peer {peer} acknowledged key change")
                else:
                    print(f"Peer {peer} failed to acknowledge key change")
                    
                conn.close()
            except Exception as e:
                print(f"Failed to notify peer {peer} of key change: {e}")

# Discover peers using mDNS
def discover_peers(local_ip, service_name, private_key, public_key):
    zeroconf = Zeroconf()
    listener = MyListener(local_ip, service_name, private_key, public_key)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    print("Discovering peers...")
    return zeroconf, browser

# Main function
if __name__ == "__main__":
    zeroconf = None
    try:
        # Generate key pair
        private_key, public_key = generate_key_pair()
        # Get local IP and service name
        local_ip = get_local_ip()
        # Register this client as a service
        zeroconf = register_service()
        # Start the server to accept connections
        threading.Thread(target=start_server, args=(private_key, public_key)).start()
        # Discover other peers
        listener = MyListener(local_ip, SERVICE_NAME, private_key, public_key)
        zeroconf, browser = discover_peers(local_ip, SERVICE_NAME, private_key, public_key)

        # Command interface
        while True:
            command = input("\nEnter command (list/peer-list/request/send/migrate/exit): ").strip().lower()
            
            if command == 'exit':
                break
                
            elif command == 'migrate':
                if listener.migrate_to_new_key():
                    print("Key migration successful")
                else:
                    print("Key migration failed")
            
            elif command == 'list':
                print("\nMy available files:", get_shared_files())
                
            elif command == 'peer-list':
                peer_ip = input("Enter peer IP: ")
                peer_port = int(input("Enter peer port: "))
                files = listener.request_peer_files(peer_ip, peer_port)
                print(f"\nFiles available from peer {peer_ip}:{peer_port}:")
                for file in files:
                    print(f"- {file}")
                
            elif command == 'request':
                peer_ip = input("Enter peer IP: ")
                peer_port = int(input("Enter peer port: "))
                filename = input("Enter filename to request: ")
                listener.request_file_from_peer(peer_ip, peer_port, filename)
                
            elif command == 'send':
                peer_ip = input("Enter peer IP: ")
                peer_port = int(input("Enter peer port: "))
                filename = input("Enter filename to send: ")
                listener.send_file_to_peer(peer_ip, peer_port, filename)
            
            else:
                print("Unknown command")

    except KeyboardInterrupt:
        print("Shutting down Client A...")
    finally:
        if zeroconf:
            zeroconf.close()