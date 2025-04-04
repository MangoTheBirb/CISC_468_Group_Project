import socket
import errno
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
from peerKeys import deserialize_public_key, KeyManager
import peerDiscovery
from peerFiles import encrypt_file_AES, decrypt_file_AES, decrypt_data_with_session_key
import time

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
    # Class-level list to track all instances
    _instances = []
    
    def __init__(self, server, peer_listener, key_manager: KeyManager):
        self._stop = threading.Event()
        self.server: socket.socket = server
        self.peer_listener = peer_listener
        self.server_thread = None
        self.key_manager = key_manager
        
        # Add this instance to the class-level tracking list
        ServerListener._instances.append(self)

        self._server_actions = {
            b"INITIAL AUTHENTICATION": self.handle_initial_authentication,
            b"REQUEST_AUTHENTICATION": self.handle_request_authentication,
            b"RENEW KEYS": self.handle_renew_keys,
            b"RENEW KEYS_ENCRYPTED": self.handle_renew_keys_encrypted,
            b"RECEIVE_FILE": self.handle_receive_file,
            b"RECEIVE_FILE_ENCRYPTED": self.handle_receive_file_encrypted,
            b"REQUEST_FILE": self.handle_request_file,
            b"REQUEST_FILE_ENCRYPTED": self.handle_request_file_encrypted,
            b"FILE_LIST_REQUEST":self.handle_file_list_request,
            b"FILE_LIST_REQUEST_ENCRYPTED":self.handle_file_list_request_encrypted,
            b"FILE_LIST_PRINT": self.handle_file_list_print,
            b"FILE_LIST_PRINT_ENCRYPTED": self.handle_file_list_print_encrypted,
            b"NO_CONSENT": self.handle_no_consent,
            b"NO_CONSENT_ENCRYPTED": self.handle_no_consent_encrypted,
            b"INITIATE_DHKE": self.handle_initiate_dhke,
            b"DHKE_RESPONSE": self.handle_dhke_response
        }

    def stop(self):
        self._stop.set()
        if self.server_thread:
            self.server_thread.join()
        # Remove this instance from the tracking list
        if self in ServerListener._instances:
            ServerListener._instances.remove(self)

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
                # Check if this is an encrypted command
                if command.endswith(b"_ENCRYPTED"):
                    print(f"Received encrypted command: {command}")
                else:
                    print(f"Unknown command: {command}")
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
                
            # The new serialized public key is in the message
            new_public_key_bytes = data[1]
            # The signature is in the third element if available
            if len(data) > 2:
                signed_key = data[2]
            else:
                raise Exception(f"Missing signature for renewed key from peer {addr}")
                
            # Deserialize the public key
            new_public_key = deserialize_public_key(new_public_key_bytes)
            
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
            
            # Update the peer's public key
            self.peer_listener.set_peer_public_key(addr[0], new_public_key)
            print(f"Peer {addr} renewed keys")
        except Exception as e:
            print(f"Failed to renew keys for peer {addr}: {e}")

    def handle_renew_keys_encrypted(self, addr, data: list):
        try:
            peer_info = self.peer_listener.peers.get(addr[0], None)
            if not peer_info:
                raise Exception(f"Peer {addr} not found")
            if peer_info.public_key is None:
                raise Exception(f"Peer {addr} has no public key")
                
            # Ensure we have the encrypted key bytes and signature
            if len(data) < 3:
                raise Exception(f"Incomplete encrypted key renewal data from peer {addr}")
                
            # Decrypt the message
            encrypted_key_bytes = data[1]
            new_public_key_bytes = self.decrypt_message_from_peer(addr[0], encrypted_key_bytes)
            
            # Get signature from data
            encrypted_signature = data[2]
            signed_key = self.decrypt_message_from_peer(addr[0], encrypted_signature)
            
            # Deserialize the public key
            new_public_key = deserialize_public_key(new_public_key_bytes)
            
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
            
            # Update the peer's public key
            self.peer_listener.set_peer_public_key(addr[0], new_public_key)
            print(f"Peer {addr} renewed keys (encrypted)")
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
        try:
            filename = data[1].decode('utf-8')
            peer_info = self.peer_listener.peers.get(addr[0], None)
            
            if not peer_info:
                raise Exception(f"Peer {addr} not found")
            
            # Display request and ask for consent
            print(f"\nPeer {peer_info.display_name} ({addr[0]}) is requesting file '{filename}'.")
            consent = input(f"Do you consent to send this file? (yes/no): ")
            
            # Restore command prompt
            print("(Command) > ", end='', flush=True)
            
            if consent.lower() == "yes":
                print(f"Sending file {filename} to {peer_info.display_name}...")
                # Rest of the file sending logic
                filepath = os.path.join(SHARED_FILES_DIR, filename)
                if not os.path.exists(filepath):
                    print(f"File {filename} not found in shared directory.")
                    peer_info.send_command(b"NO_CONSENT", f"File {filename} not found".encode())
                    return
                    
                # Get the AES key for this file
                key = self.key_manager.get_aes_key(filename)
                if not key:
                    print(f"No encryption key found for {filename}")
                    peer_info.send_command(b"NO_CONSENT", f"No encryption key found for {filename}".encode())
                    return
                    
                # Create a temporary decrypted copy
                temp_filepath = filepath + ".temp"
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                    
                # Save to temporary file
                with open(temp_filepath, "wb") as f:
                    f.write(encrypted_data)
                    
                # Decrypt the temporary file
                decrypt_file_AES(temp_filepath, key)
                
                # Read the decrypted content
                with open(temp_filepath, "rb") as f:
                    decrypted_data = f.read()
                    
                # Clean up temporary file
                os.remove(temp_filepath)
                
                # Send the file
                peer_info.send_command(b"RECEIVE_FILE", decrypted_data, filename.encode())
                print(f"File {filename} sent to {peer_info.display_name}")
            else:
                print(f"Consent denied for file {filename}")
                peer_info.send_command(b"NO_CONSENT", f"Consent denied for file {filename}".encode())
        except Exception as e:
            print(f"Error processing file request: {e}")
            # Try to notify the peer about the error
            try:
                if peer_info:
                    peer_info.send_command(b"NO_CONSENT", f"Error: {str(e)}".encode())
            except:
                pass

    def handle_file_list_print(self, addr, data):
        try:
            # First print a newline to separate from the current command line
            print("\n")
            file_list = data[1].decode('utf-8').split('\n')
            peer_info = self.peer_listener.peers.get(addr[0], None)
            peer_name = peer_info.display_name if peer_info else addr[0]
            
            print(f"Files from peer {peer_name}:")
            for file in file_list:
                if file.strip():
                    print(f"- {file}")
            
            # Restore command prompt
            print("(Command) > ", end='', flush=True)
        except Exception as e:
            print(f"Error displaying file list: {e}")
            # Restore command prompt
            print("(Command) > ", end='', flush=True)

    def handle_file_list_request(self, addr, data):
        try:
            peer_info = self.peer_listener.peers.get(addr[0], None)
            peer_name = peer_info.display_name if peer_info else addr[0]
            
            print(f"\nPeer {peer_name} is requesting your file list.")
            consent = input("Do you consent to share your file list? (yes/no): ")
            
            # Restore command prompt
            print("(Command) > ", end='', flush=True)
            
            if consent.lower() == "yes":
                # Send our file list to the peer
                from peerFiles import get_shared_files
                files = get_shared_files()
                
                if not files:
                    # If no files to share
                    if peer_info:
                        peer_info.send_command(b"FILE_LIST_PRINT", "No shared files available".encode())
                    print(f"Sent empty file list to {peer_name}")
                    return
                
                # Send the list of files to the peer
                file_list = "\n".join(files).encode()
                if peer_info:
                    peer_info.send_command(b"FILE_LIST_PRINT", file_list)
                    print(f"Sent file list to {peer_name}")
            else:
                print(f"Denied file list request from {peer_name}")
                if peer_info:
                    peer_info.send_command(b"NO_CONSENT", "File list request denied".encode())
        except Exception as e:
            print(f"Error handling file list request: {e}")
            # Restore command prompt
            print("(Command) > ", end='', flush=True)

    def handle_no_consent(self,addr,data):
        print("hanlde_no_consent", data)
        #print if they want to receive file
        print(f"Peer {addr} has denied consent")
    
    def handle_initiate_dhke(self, addr, data):
        """Handle a Diffie-Hellman Key Exchange initiation from a peer"""
        try:
            peer_info = self.peer_listener.peers.get(addr[0], None)
            if not peer_info:
                raise Exception(f"Peer {addr} not found")
            if peer_info.public_key is None:
                raise Exception(f"Peer {addr} has no public key")
                
            # Get data from the request
            parameters_bytes = data[1]
            dh_public_key_bytes = data[2]
            signature = data[3]
            
            # Respond to the DHKE initiation
            peer_info.respond_to_dhke(parameters_bytes, dh_public_key_bytes, signature)
            
            print(f"Processed DHKE initiation from peer {addr}")
        except Exception as e:
            print(f"Failed to process DHKE initiation from peer {addr}: {e}")
    
    def handle_dhke_response(self, addr, data):
        """Handle a Diffie-Hellman Key Exchange response from a peer"""
        try:
            print(f"Received DHKE response from {addr}")
            peer_info = self.peer_listener.peers.get(addr[0], None)
            if not peer_info:
                print(f"Peer {addr} not found in peer list")
                raise Exception(f"Peer {addr} not found")
                
            if peer_info.public_key is None:
                print(f"Peer {addr} has no public key")
                # Try to authenticate before failing
                print(f"Attempting authentication with peer {addr}")
                self.request_authentication_from_peer(peer_info)
                time.sleep(1)  # Wait for authentication to complete
                
                if peer_info.public_key is None:
                    raise Exception(f"Peer {addr} has no public key even after authentication")
                
            # Get data from the response
            dh_public_key_bytes = data[1]
            signature = data[2]
            
            print(f"DHKE response data length - Public key: {len(dh_public_key_bytes)}, Signature: {len(signature)}")
            
            # Process the DHKE response
            success = peer_info.handle_dhke_response(dh_public_key_bytes, signature)
            
            if success:
                print(f"Successfully processed DHKE response from peer {addr}")
            else:
                print(f"Failed to process DHKE response from peer {addr}")
                
        except Exception as e:
            print(f"Failed to process DHKE response from peer {addr}: {e}")
    
    def request_authentication_from_peer(self, peer_info):
        """Request authentication from a peer"""
        if hasattr(peer_info, 'request_authentication_from_peer'):
            return peer_info.request_authentication_from_peer()
        else:
            print(f"Peer {peer_info.ip} does not have request_authentication_from_peer method")

    def decrypt_message_from_peer(self, peer_ip, encrypted_data):
        """Decrypt message from peer using the appropriate session key"""
        try:
            peer = self.peer_listener.peers.get(peer_ip)
            if not peer:
                raise Exception(f"Peer {peer_ip} not found")
                
            # Get the session for this peer
            session = peer.active_sessions.get(peer_ip)
            if not session or not session.session_key:
                raise Exception(f"No active session with key for peer {peer_ip}")
                
            # Decrypt the message
            return decrypt_data_with_session_key(encrypted_data, session.session_key)
        except Exception as e:
            print(f"Failed to decrypt message from peer {peer_ip}: {e}")
            raise
    
    def handle_receive_file_encrypted(self, addr, data):
        """Handle an encrypted file receive request"""
        try:
            # Get the filename
            filename = data[1].decode('utf-8')
            
            # Get the encrypted file content
            encrypted_content = data[2]
            
            # Decrypt the file content
            file_content = self.decrypt_message_from_peer(addr[0], encrypted_content)
            
            # Process the file as usual
            filepath = os.path.join(SHARED_FILES_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(file_content)
                
            # Generate a 32-byte key for AES-256 and encrypt the file
            key = os.urandom(32)
            self.key_manager.store_aes_key(filename, key)
            encrypt_file_AES(filepath, key)
            
            print(f"Received, decrypted, and re-encrypted file {filename} from {addr}")
        except Exception as e:
            print(f"Failed to handle encrypted received file: {e}")
    
    def handle_request_file_encrypted(self, addr, data):
        """Handle an encrypted file request"""
        try:
            # Decrypt the request message
            encrypted_message = data[1]
            message = self.decrypt_message_from_peer(addr[0], encrypted_message)
            
            # Process as normal file request with the decrypted message
            print(f"Peer {addr} is requesting file {message.decode('utf-8')}.", end="", flush=True)
            consent = input("Do you consent? (yes/no): ")
            
            peer = self.peer_listener.peers.get(addr[0])
            
            if consent != "yes":
                str = f"Denied consent to give file: {message.decode('utf-8')}"
                peer.send_command(b"REQUEST_FILE", str.encode())
                return
            
            filename = message.decode('utf-8')
            filepath = os.path.join(SHARED_FILES_DIR, filename)
            
            if not os.path.exists(filepath):
                print(f"File {filepath} does not exist.")
                return
                
            try:
                with open(filepath, "rb") as f:
                    file_data = f.read()
                # Send the file data to the peer (it will be encrypted in send_command if a session exists)
                peer.send_command(b"RECEIVE_FILE", file_data, filename.encode())
                print(f"Successfully sent file {filename} to {peer.display_name}")
            except Exception as e:
                print(f"Error sending file: {e}")
        except Exception as e:
            print(f"Failed to handle encrypted file request: {e}")
    
    def handle_file_list_request_encrypted(self, addr, data):
        """Handle an encrypted file list request"""
        try:
            # Decrypt the request message
            encrypted_message = data[1]
            file_list = self.decrypt_message_from_peer(addr[0], encrypted_message)
            
            peer = self.peer_listener.peers.get(addr[0])
            
            print(f"Peer {addr} is requesting file list.", end="", flush=True)
            consent = input("Do you consent? (yes/no): ")
            
            if consent.lower() != "yes":
                print("Sending denied consent")
                peer.send_command(b"NO_CONSENT", b"File list request denied")
                return
                
            # If consent given, send the file list
            peer.send_command(b"FILE_LIST_PRINT", file_list)
        except Exception as e:
            print(f"Failed to handle encrypted file list request: {e}")
    
    def handle_file_list_print_encrypted(self, addr, data):
        """Handle an encrypted file list print"""
        try:
            # Decrypt the file list
            encrypted_file_list = data[1]
            file_list = self.decrypt_message_from_peer(addr[0], encrypted_file_list)
            
            # Split by newline and decode
            file_list = file_list.split(b"\n")
            file_list = [file.decode('utf-8') for file in file_list]
            
            # Print the file list
            print(f"Peer {addr} has the following files:")
            for file in file_list:
                print(file)
        except Exception as e:
            print(f"Failed to handle encrypted file list print: {e}")
    
    def handle_no_consent_encrypted(self, addr, data):
        """Handle an encrypted no consent message"""
        try:
            # Decrypt the message
            encrypted_message = data[1]
            message = self.decrypt_message_from_peer(addr[0], encrypted_message)
            
            print(f"Peer {addr} has denied consent: {message.decode('utf-8')}")
        except Exception as e:
            print(f"Failed to handle encrypted no consent message: {e}")

    def handle_request_authentication(self, addr, data: list):
        """Handle a request for authentication from a peer"""
        try:
            # Process like initial authentication
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
            
            # Set the peer's public key
            self.peer_listener.set_peer_public_key(addr[0], peer_public_key)
            print(f"Peer {addr} authenticated via request")
            
            # Authenticate back to the peer
            peer_info = self.peer_listener.peers.get(addr[0])
            if peer_info:
                print(f"Authenticating back to peer {addr}")
                peer_info.authenticate_self_to_peer()
            else:
                print(f"Peer {addr} not found in peer list, cannot authenticate back")
                
        except Exception as e:
            print(f"Failed to handle authentication request from peer {addr}: {e}")

