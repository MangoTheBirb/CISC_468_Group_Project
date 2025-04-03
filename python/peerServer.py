import socket
import errno
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
from peerKeys import deserialize_public_key, KeyManager
import peerDiscovery
from peerFiles import encrypt_file_AES, decrypt_file_AES

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
            b"REQUEST_FILE": self.handle_request_file,
            b"FILE_LIST_REQUEST":self.handle_file_list_request,
            b"FILE_LIST_PRINT": self.handle_file_list_print,
            b"NO_CONSENT": self.handle_no_consent
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
        try:
            print(data)
            # Get the filename from data list (decode filename since it's text)
            filename = data[1].decode('utf-8')
            # Keep file_content as bytes without decoding
            file_content = data[2]
            
            # First save the received file
            filepath = os.path.join(SHARED_FILES_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(file_content)
            print(filepath)
            # Generate a 32-byte (256-bit) key for AES-256
            key = os.urandom(32)
            self.key_manager.store_aes_key(filename, key)

            # Encrypt the saved file
            encrypt_file_AES(filepath, key)
            
            print(f"Received and encrypted file {filename} from {addr}")
            
            # You might want to store or share the key securely
            # For now, we'll just print it (in practice, you'd want to handle this more securely)
            print(f"Encryption key (hex): {key.hex()}")

            #key = self.key_manager.get_aes_key(filename)
            #print(f"Decryption key (hex): {key.hex()}")
            # Decrypt the file for verification (optional)
            #decrypt_file_AES(filepath, key)


            
            

            
        except Exception as e:
            print(f"Failed to handle received file: {e}")

    def handle_request_file(self, addr, data):
        # print("addr", addr)
        # print("data", data)

        #print if they want to receive file
        #print(data[1])

        #receive input
        print(f"Peer {addr} is requesting file {data[1].decode('utf-8')}.", end="", flush=True)
        consent = input("Do you consent? (yes/no): ")
        
        peer = self.peer_listener.peers.get(addr[0])

        if consent != "yes":
            str = "Denied consent to give file: {data[1]}"
            peer.send_command(b"REQUEST_FILE", str.encode())
            return
        
        peer_display_name = peer.name
        
        #find peer using addr
        filename = data[1].decode('utf-8')

        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist.")
            return
            
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            # Send the file data to the peer
            peer.send_command(b"RECEIVE_FILE", file_data, filename.encode())
            print(f"Successfully sent file {filename} to {peer_display_name}")
        except Exception as e:
            print(f"Error sending file: {e}")

    def handle_file_list_print(self, addr, data):
        print(addr)
        print(data)

        #example: b'123.txt\ntest.xt'
        file_list = data[1]

        #split by \n
        file_list = file_list.split(b"\n")
        #decode each file name to utf-8
        file_list = [file.decode('utf-8') for file in file_list]
        #print file_list
        print(f"Peer {addr} has the following files:")
        for file in file_list:
            print(file)

    def handle_file_list_request(self, addr, data):
        file_list = data[1]
        peer = self.peer_listener.peers.get(addr[0])
        
        # Fix: Remove the input() around print() and get consent properly
        print(f"Peer {addr} is requesting file list.", end="", flush=True)
        consent = input("Do you consent? (yes/no): ")
        
        if consent.lower() != "yes":
            print("Sending denied consent")
            peer.send_command(b"NO_CONSENT", b"File list request denied")
            return
            
        # If consent given, send the file list
        peer.send_command(b"FILE_LIST_PRINT", file_list)

    def handle_no_consent(self,addr,data):
        print("hanlde_no_consent", data)
        #print if they want to receive file
        print(f"Peer {addr} has denied consent")

