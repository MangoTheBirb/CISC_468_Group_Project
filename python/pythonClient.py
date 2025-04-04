import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

from peerDiscovery import register_service, discover_peers
from peerServer import start_server, ServerListener
from peerKeys import KeyManager, serialize_public_key, deserialize_public_key
from peerCli import CliManager
from peerFiles import initialize_shared_files, get_shared_files, encrypt_data_with_session_key, decrypt_data_with_session_key

# Configuration
SERVICE_NAME_TEMPLATE = "Peer-{hostname}._p2pfileshare._tcp.local."

# Change working directory to the script's directory
os.chdir(os.path.dirname(os.path.realpath(__file__)))

# Get the local IP address
def get_local_ip():
    temp_sock = None
    try:
        # Create a temporary socket to get the local IP address
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.connect(("8.8.8.8", 80))  # Google's public DNS server
        local_ip = temp_sock.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return "127.0.0.1"  # Fallback to localhost
    finally:
        if temp_sock:
            temp_sock.close()

# Send a file to a peer
def send_file(conn, filename, directory="shared_files"):
    filepath = os.path.join(directory, filename)
    try:
        with open(filepath, "rb") as f:
            conn.sendall(f.read())
        print(f"Sent file {filename}")
    except Exception as e:
        print(f"Error sending file {filename}: {e}")

# Receive a file from a peer
def receive_file(conn, filename, directory="shared_files"):
    filepath = os.path.join(directory, filename)
    try:
        with open(filepath, "wb") as f:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                f.write(data)
        print(f"Received file {filename} at {filepath}")
    except Exception as e:
        print(f"Error receiving file {filename}: {e}")

# Handle incoming connections
# filepath: c:\Users\ww2ct\Documents\GitHub\CISC_468_Group_Project\pythonClientB.py
def request_file_list(peer_ip, peer_port):
    try:
        conn = socket.create_connection((peer_ip, peer_port))
        conn.sendall("REQUEST_FILE_LIST".encode())
        file_list = conn.recv(4096).decode().split("\n")
        conn.close()
        return file_list
    except Exception as e:
        print(f"Failed to request file list from {peer_ip}:{peer_port}: {e}")
        return []

# filepath: c:\Users\ww2ct\Documents\GitHub\CISC_468_Group_Project\pythonClientB.py
def handle_client(conn, addr, private_key, public_key):
    print(f"Connected to {addr}")
    try:
        # Exchange public keys
        conn.sendall(serialize_public_key(public_key))
        peer_public_key_bytes = conn.recv(2048)  # Increase buffer size
        print(f"Received public key bytes from {addr}: {peer_public_key_bytes}")
        peer_public_key = deserialize_public_key(peer_public_key_bytes)
        print(f"Received public key from {addr}")

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
        print(f"Identity of {addr} verified")

        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            if data == "REQUEST_FILE_LIST":
                files = get_shared_files()
                conn.sendall("\n".join(files).encode())
            elif data.startswith("REQUEST_FILE:"):
                filename = data.split(":", 1)[1]
                consent = input(f"Peer {addr} is requesting file '{filename}'. Do you consent? (yes/no): ")
                if consent.lower() == "yes":
                    send_file(conn, filename)
                else:
                    print(f"Consent denied for file '{filename}'")
            elif data.startswith("SEND_FILE:"):
                filename = data.split(":", 1)[1]
                consent = input(f"Peer {addr} wants to send file '{filename}'. Do you consent? (yes/no): ")
                if consent.lower() == "yes":
                    receive_file(conn, filename)
                else:
                    print(f"Consent denied for file '{filename}'")
            else:
                print(f"Received from {addr}: {data}")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

# filepath: c:\Users\ww2ct\Documents\GitHub\CISC_468_Group_Project\pythonClientB.py
def request_file(peer_ip, peer_port, filename):
    try:
        conn = socket.create_connection((peer_ip, peer_port))
        conn.sendall(f"REQUEST_FILE:{filename}".encode())
        receive_file(conn, filename)
        conn.close()
    except Exception as e:
        print(f"Failed to request file {filename} from {peer_ip}:{peer_port}: {e}")

def send_file_to_peer(peer_ip, peer_port, filename):
    try:
        conn = socket.create_connection((peer_ip, peer_port))
        conn.sendall(f"SEND_FILE:{filename}".encode())
        send_file(conn, filename)
        conn.close()
    except Exception as e:
        print(f"Failed to send file {filename} to {peer_ip}:{peer_port}: {e}")

# Main function
def main():
    zeroconf = None
    server_thread = None
    peer_browser = None
    server = None
    try:
        # Initialize shared files directory
        initialize_shared_files()
        # Generate key pair
        key_manager = KeyManager()
        # Start the server to accept connections
        server, server_port = start_server()
        print(f"Server started on port {server_port}")
        # Get local IP and service name
        client_name = SERVICE_NAME_TEMPLATE.format(hostname=socket.gethostname())
        local_ip = get_local_ip()
        # Register this client as a service
        zeroconf = register_service(server_port, client_name, local_ip)
        # Discover other peers
        peer_browser, peer_listener = discover_peers(zeroconf, local_ip, client_name, key_manager)
        # Start a thread to listen for incoming connections
        server_thread = ServerListener(server, peer_listener, key_manager)
        server_thread.run()
        print("Client has started listening for connections.")
        # Start CLI
        cli_manager = CliManager(peer_listener, key_manager)
        cli_manager.cmdloop()
    except KeyboardInterrupt:
        print("Shutting down Client...")
    finally:
        if peer_browser:
            print("Stopping Peer Discovery")
            peer_browser.cancel()
        if zeroconf:
            print("Unregistering Client...")
            zeroconf.close()
        if server_thread:
            print("Stopping Server...")
            server_thread.stop()
            server.close()
        print("Client shutdown complete")

if __name__ == "__main__":
    main()