import socket
import threading
import os
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Configuration
SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "ClientA._p2pfileshare._tcp.local."
PORT = 5000

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

# Handle incoming connections
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
            handle_client(conn, (peer_ip, peer_port), self.private_key, self.public_key)
        except Exception as e:
            print(f"Failed to connect to peer {peer_ip}:{peer_port}: {e}")

    def remove_service(self, zeroconf, type, name):
        print(f"Service removed: {name}")

    def update_service(self, zeroconf, type, name):
        print(f"Service updated: {name}")

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
            command = input("\nEnter command (list/request/send/exit): ").strip().lower()
            
            if command == 'exit':
                break
                
            elif command == 'list':
                print("\nAvailable files:", get_shared_files())
                
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