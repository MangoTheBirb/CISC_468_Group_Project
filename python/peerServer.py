import socket
import errno
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
from peerKeys import deserialize_public_key, KeyManager
import peerDiscovery
START_PORT = 5000
MAX_PORT = 65535
SHARED_FILES_DIR = "shared_files"
# Start server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = START_PORT
    while True:
        try:
            server.bind(("0.0.0.0", port))  # Bind to all available interfaces
            break
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                port += 1
                if port > MAX_PORT:
                    raise Exception("No available ports")
    server.listen()
    return server, port

class ServerListener():
    def __init__(self, server, peer_listener, key_manager: KeyManager):
        self._stop = threading.Event()
        self.server: socket.socket = server
        self.peer_listener = peer_listener
        self.server_thread = None
        self.key_manager = key_manager

        self._server_actions = {
            b"INITIAL AUTHENTICATION": self.handle_initial_authentication,
            b"RENEW KEYS": self.handle_renew_keys,
            b"RECEIVE_FILE": self.handle_receive_file,
            b"REQUEST_FILE": self.handle_request_file, #change later
            b"RECEIVE_CONSENT": self.handle_receive_consent
        }

    def stop(self):
        self._stop.set()
        if self.server_thread:
            self.server_thread.join()

    def stopped(self):
        return self._stop.isSet()
    
    def run(self):
        self.server_thread = threading.Thread(target=self.server_listener)
        self.server_thread.start()

    def server_listener(self):
        self.server.settimeout(0.2)
        while True:
            if self.stopped():
                break
            try:
                conn, addr = self.server.accept()
                if self.stopped():
                    break
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
            except socket.timeout:
                pass
    
    def handle_client(self, conn: socket.socket, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return
            data = data.split(b"\r\n")
            command = data[0]
            handler: callable = self._server_actions.get(command, None)
            if not handler:
                raise Exception(f"Unknown command: {command}")
            handler(addr, data)
        except Exception as e:
            print(f"Error receiving data from {addr}: {e}")
            return
        finally:
            conn.close()
        
    def handle_initial_authentication(self, addr, data: list):
        try:
            nonce = data[1]
            signed_nonce = data[2]
            peer_public_key = deserialize_public_key(data[3])
            # Verify the signed nonce
            peer_public_key.verify(
                signed_nonce,
                nonce,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.peer_listener.set_peer_public_key(addr[0], peer_public_key)
            print(f"Peer {addr} authenticated")
        except Exception as e:
            print(f"Failed to authenticate peer {addr}: {e}")

    def handle_renew_keys(self, addr, data: list):
        try:
            peer_info = self.peer_listener.peers.get(addr[0], None)
            if not peer_info:
                raise Exception(f"Peer {addr} not found")
            if peer_info.public_key is None:
                raise Exception(f"Peer {addr} has no public key")
            new_public_key_bytes = data[1]
            new_public_key = deserialize_public_key(new_public_key_bytes)
            signed_key = data[2]
            # Verify the signed key
            peer_info.public_key.verify(
                signed_key,
                new_public_key_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.peer_listener.set_peer_public_key(addr[0], new_public_key)
            print(f"Peer {addr} renewed keys")
        except Exception as e:
            print(f"Failed to renew keys for peer {addr}: {e}")


    def handle_receive_file(self, addr, data):
        print("addr", addr)
        print("data", data)
        
        try:
            # Get the filename from data list (decode filename since it's text)
            filename = data[1].decode('utf-8')
            # Keep file_content as bytes without decoding
            file_content = data[2]
            
            # Save the file in binary mode
            with open(filename, "wb") as f:
                f.write(file_content)
            print(f"Received file {filename} from {addr}")
            
        except Exception as e:
            print(f"Failed to save file {filename}: {e}")

    def handle_request_file(self,addr,data):
        print("addr", addr)
        print("data", data)

        #print if they want to receive file
        #print(data[1])

        #receive input
        consent = input(f"Peer {addr} is requesting file {data[1]}. Do you consent? (yes/no): ")

        peer = self.peer_listener.peers.get(addr[0])
        print("peer", peer)
        peer_display_name = peer.name
        #find peer using addr
        filename = data[1].decode('utf-8')
        peer_display_name = peer.name

        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist.")
            return
            
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            # Send the file data to the peer
            peer.send_command(b"RECEIVE_FILE", file_data,filename.encode())
            print(f"Successfully sent file {filename} to {peer_display_name}")
        except Exception as e:
            print(f"Error sending file: {e}")
        pass
        peer.send_command(b"RECEIVE_FILE",file_data,filename.encode())
        #peer.send_command(b"RECEIVE_CONSENT", consent.encode(),data[1])

    def handle_receive_consent(self, addr, data):
        print("addr", addr)
        print("data", data)
        # Handle the consent to receive a file from the peer
        peer = self.peer_listener.peers.get(addr[0])
        if not peer:
            print(f"No peer found for address {addr[0]}")
            return
        
        if data[2] == b"yes":
            print("Peer consented to receive the file.")
            # Proceed with file transfer logic here
        else:
            print("Peer declined the file transfer.")
        #cmd line should be peer_display_name filename
        filename = data[1].decode('utf-8')
        peer_display_name = peer.name

        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist.")
            return
            
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            # Send the file data to the peer
            peer.send_command(b"RECEIVE_FILE", file_data,filename.encode())
            print(f"Successfully sent file {filename} to {peer_display_name}")
        except Exception as e:
            print(f"Error sending file: {e}")
        pass
