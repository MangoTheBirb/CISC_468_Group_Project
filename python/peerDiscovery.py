from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener
import os
import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
import base64

from peerKeys import serialize_public_key, KeyManager

SERVICE_TYPE = "_p2pfileshare._tcp.local."

# Global DH parameters - generate only once to improve performance
DH_PARAMETERS = None

def get_dh_parameters():
    """Get global DH parameters, generating them if necessary."""
    global DH_PARAMETERS
    if DH_PARAMETERS is None:
        print("Generating DH parameters (this may take a moment)...")
        DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)
        print("DH parameters generated.")
    return DH_PARAMETERS

# Register the service using mDNS
def register_service(port, client_name, local_ip):
    info = ServiceInfo(
        SERVICE_TYPE,
        client_name,
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={"display_name": socket.gethostname()},
    )
    zeroconf = Zeroconf()
    zeroconf.register_service(info)
    print(f"Client registered as {client_name} at {local_ip}:{port}")
    return zeroconf

# Discover peers using mDNS
def discover_peers(zeroconf, local_ip, service_name, key_manager: KeyManager):
    listener = PeerConnectionListener(local_ip, service_name, key_manager)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    print("Started Peer Discovery")
    return browser, listener

def generate_shared_key(private_key, peer_public_key):
    try:
        print("Generating shared key")
        shared_key = private_key.exchange(peer_public_key)
        print("Successfully generated shared key")
        
        print("Deriving key using HKDF")
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        print("Successfully derived key using HKDF")
        return derived_key
    except Exception as e:
        print(f"Failed to generate shared key: {e}")
        raise

def verify_dh_public_key(rsa_public_key, dh_public_key_bytes, signature):
    try:
        print("Verifying DH public key signature")
        print(f"Signature length: {len(signature)}")
        print(f"DH public key bytes length: {len(dh_public_key_bytes)}")
        
        # Debug the first few bytes of each
        print(f"First 20 bytes of signature: {signature[:20]}")
        print(f"First 20 bytes of DH public key: {dh_public_key_bytes[:20]}")
        
        rsa_public_key.verify(
            signature,
            dh_public_key_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Successfully verified DH public key signature")
        return True
    except Exception as e:
        print(f"Failed to verify DH public key signature: {str(e)}")
        # Try alternative verification method if original fails
        try:
            print("Attempting alternative verification method...")
            # Try with a more relaxed salt length parameter
            rsa_public_key.verify(
                signature,
                dh_public_key_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32  # Fixed salt length
                ),
                hashes.SHA256()
            )
            print("Alternative verification succeeded")
            return True
        except Exception as alt_e:
            print(f"Alternative verification also failed: {str(alt_e)}")
            return False

class PeerInfo():
    def __init__(self, name, ip, port, properties, key_manager: KeyManager):
        self.name = name
        self.ip = ip
        self.port = port
        self.properties = properties
        self.public_key = None
        self.display_name = properties.get(b"display_name", b"").decode("utf-8")
        self.key_manager = key_manager
        self.active_sessions = {}

    def authenticate_self_to_peer(self):
        conn = None
        try:
            message = b"INITIAL AUTHENTICATION"
            nonce = os.urandom(16)
            signed_nonce = self.key_manager.sign_message(nonce)
            conn = socket.create_connection((self.ip, self.port))
            conn.sendall(message + b"\r\n" + nonce + b"\r\n" + signed_nonce + b'\r\n' + self.key_manager.get_serialized_public_key())
        except Exception as e:
            print(f"Failed to connect to peer {self.ip}:{self.port}: {e}")
        finally:
            if conn:
                conn.close()
    
    def initiate_dhke(self):
        """Initiates Diffie-Hellman Key Exchange with the peer"""
        if not self.public_key:
            raise Exception(f"Cannot initiate DHKE with peer {self.ip}: No public key")
        
        conn = None
        try:
            try:
                print(f"Getting or creating session for peer {self.ip}")
                if self.ip not in self.active_sessions:
                    print(f"Creating new session for peer {self.ip}")
                    session = DHKESession(self.key_manager, self.ip)
                    # Set parameters and initialize explicitly
                    session.parameters = get_dh_parameters()
                    session.initialize()
                    self.active_sessions[self.ip] = session
                session = self.active_sessions[self.ip]
            except Exception as e:
                print(f"Failed to get or create session for peer {self.ip}: {e}")
                raise
            
            # Get our DH public key and sign it with our RSA private key
            dh_public_key_bytes, signature = session.get_public_key_and_signature()
            
            # Parameters need to be shared for both parties to use the same parameters
            parameters_bytes = session.parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            
            # Send DHKE initiation message
            message = b"INITIATE_DHKE"
            conn = socket.create_connection((self.ip, self.port))
            conn.sendall(message + b"\r\n" + parameters_bytes + b"\r\n" + dh_public_key_bytes + b"\r\n" + signature)
            
            print(f"Initiated DHKE with peer {self.ip}")
            return True
        except Exception as e:
            print(f"Failed to initiate DHKE with peer {self.ip}: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def handle_dhke_response(self, peer_dh_public_key_bytes, peer_signature):
        """Process the peer's DH response to complete the key exchange"""
        if not self.public_key:
            raise Exception(f"Cannot complete DHKE with peer {self.ip}: No public key")
        
        try:
            # Get the session for this peer
            session = self.active_sessions.get(self.ip)
            if not session:
                raise Exception(f"No active DHKE session for peer {self.ip}")
            
            print(f"Processing DHKE response from peer {self.ip}")
            print(f"DH public key bytes length: {len(peer_dh_public_key_bytes)}")
            print(f"Signature length: {len(peer_signature)}")
            
            # Verify the signature before processing
            verification_result = verify_dh_public_key(self.public_key, peer_dh_public_key_bytes, peer_signature)
            if not verification_result:
                # If verification fails, try one more time with re-authentication
                print(f"Signature verification failed. Attempting to re-authenticate with peer {self.ip}")
                self.authenticate_self_to_peer()
                time.sleep(1)  # Wait for authentication to complete
                
                # Try verification again
                verification_result = verify_dh_public_key(self.public_key, peer_dh_public_key_bytes, peer_signature)
                if not verification_result:
                    raise Exception(f"Failed to verify DH public key signature from peer {self.ip}")
            
            # Process the peer's public key and generate the shared session key
            try:
                # Load the peer's public key
                peer_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes)
                session.peer_public_key = peer_public_key
                
                # Generate the shared key
                print(f"Generating shared key with peer {self.ip}")
                session.session_key = generate_shared_key(session.private_key, session.peer_public_key)
                print(f"Successfully generated shared key with peer {self.ip}")
                
                print(f"Completed DHKE with peer {self.ip}, session key established")
                return True
            except Exception as e:
                print(f"Error processing peer's public key: {e}")
                raise
        except Exception as e:
            print(f"Failed to complete DHKE with peer {self.ip}: {e}")
            return False

    def respond_to_dhke(self, parameters_bytes, peer_dh_public_key_bytes, peer_signature):
        """Respond to a DHKE initiation from a peer"""
        if not self.public_key:
            raise Exception(f"Cannot respond to DHKE from peer {self.ip}: No public key")
        
        conn = None
        try:
            # Verify the peer's DH public key signature using their RSA public key
            if not verify_dh_public_key(self.public_key, peer_dh_public_key_bytes, peer_signature):
                # If verification fails, try to re-authenticate with the peer before failing
                print(f"Signature verification failed. Attempting to re-authenticate with peer {self.ip}")
                self.authenticate_self_to_peer()
                time.sleep(1)  # Wait for authentication to complete
                
                # Try verification again with potentially updated public key
                if not verify_dh_public_key(self.public_key, peer_dh_public_key_bytes, peer_signature):
                    raise Exception(f"Invalid signature from peer {self.ip} even after re-authentication")
            
            # Deserialize the DH parameters
            print(f"Loading parameters from peer {self.ip}")
            try:
                parameters = serialization.load_pem_parameters(parameters_bytes)
                # Validate parameters by trying to generate a key
                test_key = parameters.generate_private_key()
                print(f"Successfully validated parameters from peer {self.ip}")
            except Exception as param_error:
                print(f"Error loading parameters from peer: {param_error}")
                print("Using local parameters instead")
                parameters = get_dh_parameters()
            
            # Create a new session using the received parameters
            session = DHKESession(self.key_manager, self.ip)
            # Use the received parameters directly instead of generating new ones
            session.parameters = parameters
            print("Initializing with peer's parameters")
            session.initialize()  # Generate our own key pair using the peer's parameters
            
            # Store the session
            self.active_sessions[self.ip] = session
            
            # Set peer's public key
            try:
                session.peer_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes)
            except Exception as key_error:
                print(f"Error loading peer's public key: {key_error}")
                raise
            
            # Generate shared session key
            session.session_key = generate_shared_key(session.private_key, session.peer_public_key)
            
            # Get our DH public key and sign it with our RSA private key
            our_dh_public_key_bytes, our_signature = session.get_public_key_and_signature()
            
            # Send our DH response
            message = b"DHKE_RESPONSE"
            conn = socket.create_connection((self.ip, self.port))
            conn.sendall(message + b"\r\n" + our_dh_public_key_bytes + b"\r\n" + our_signature)
            
            print(f"Responded to DHKE from peer {self.ip}, session key established")
            return True
        except Exception as e:
            print(f"Failed to respond to DHKE from peer {self.ip}: {e}")
            return False
        finally:
            if conn:
                conn.close()
                
    def encrypt_message(self, message):
        """Encrypt a message using the established session key"""
        # Get session and its session_key
        session = self.active_sessions.get(self.ip)
        if not session or not session.session_key:
            # Try to establish a session if one doesn't exist
            if not self.initiate_dhke():
                raise Exception(f"Cannot encrypt message: No session key for peer {self.ip}")
            # Wait briefly for DHKE to complete (in a real implementation, you'd wait for confirmation)
            # For now, we'll throw an exception as we don't have a mechanism to wait for completion
            raise Exception(f"Session key not yet established with peer {self.ip}. Try again after DHKE completes.")
        
        # Import here to avoid circular imports
        from peerFiles import encrypt_data_with_session_key
        return encrypt_data_with_session_key(message, session.session_key)
        
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using the established session key"""
        # Get session and its session_key
        session = self.active_sessions.get(self.ip)
        if not session or not session.session_key:
            raise Exception(f"Cannot decrypt message: No session key for peer {self.ip}")
        
        # Import here to avoid circular imports
        from peerFiles import decrypt_data_with_session_key
        return decrypt_data_with_session_key(encrypted_message, session.session_key)
    
    def request_authentication_from_peer(self):
        """Request authentication from this peer"""
        try:
            conn = socket.create_connection((self.ip, self.port))
            message = b"REQUEST_AUTHENTICATION"
            nonce = os.urandom(16)
            signed_nonce = self.key_manager.sign_message(nonce)
            conn.sendall(message + b"\r\n" + nonce + b"\r\n" + signed_nonce + b'\r\n' + self.key_manager.get_serialized_public_key())
            print(f"Sent authentication request to peer {self.ip}")
            # Wait a short time for peer to process
            time.sleep(1)
            return True
        except Exception as e:
            print(f"Failed to request authentication from peer {self.ip}: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def send_command(self, command, message=None, signed_data=None, filename=None):
        conn = None
        print(f"Sending command {command} to peer {self.ip}:{self.port}")
        print(f"Message: {message}")
        
        try:
            # If we don't have the peer's public key, try to authenticate first
            if not self.public_key:
                print(f"No public key for peer {self.ip}, attempting authentication")
                self.authenticate_self_to_peer()
                # Wait a short time for peer to process our authentication
                time.sleep(1)
                
                # If we still don't have a public key, try requesting authentication
                if not self.public_key:
                    print(f"Still no public key, requesting authentication from peer {self.ip}")
                    self.request_authentication_from_peer()
                    
                    # Wait again for potential response
                    time.sleep(1)
            
            # Only sign the message if no signed data was explicitly provided
            if not signed_data and message is not None:
                signed_data = self.key_manager.sign_message(message)
            
            # Check for active session
            session = self.active_sessions.get(self.ip)
            if not session or not session.session_key:
                try:
                    if self.public_key:  # Only try DHKE if we have a public key
                        print("No session key established. Initiating DHKE...")
                        if not self.initiate_dhke():
                            print("Failed to initiate DHKE. Proceeding without encryption.")
                        else:
                            # Wait briefly for DHKE response (This is a simplification)
                            # In a real implementation, you'd have a synchronization mechanism
                            # or explicit acknowledgement from the peer
                            time.sleep(1)  # Wait briefly for DHKE to complete
                            # Check again if we have a session with key
                            session = self.active_sessions.get(self.ip)
                    else:
                        print(f"Cannot initiate DHKE with peer {self.ip}: No public key. Proceeding without encryption.")
                except Exception as e:
                    print(f"DHKE failed: {e}. Proceeding without encryption.")
            
            conn = socket.create_connection((self.ip, self.port))
            
            # If we have a session with key, encrypt the message
            if session and session.session_key:
                # Import encryption function here to avoid circular imports
                from peerFiles import encrypt_data_with_session_key
                
                # Add a flag to indicate this message is encrypted
                command_with_flag = command + b"_ENCRYPTED"
                
                # Encrypt the message using the session key
                if message:
                    encrypted_message = encrypt_data_with_session_key(message, session.session_key)
                else:
                    # If there's no message, create an empty encrypted message
                    encrypted_message = encrypt_data_with_session_key(b"", session.session_key)
                
                # Encrypt signed data if it exists
                if signed_data:
                    encrypted_signed_data = encrypt_data_with_session_key(signed_data, session.session_key)
                else:
                    encrypted_signed_data = encrypt_data_with_session_key(b"", session.session_key)
                
                # Send the command with encrypted message and encrypted signed data
                if filename:
                    conn.sendall(command_with_flag + b"\r\n" + filename + b"\r\n" + encrypted_message + b"\r\n" + encrypted_signed_data)
                else:
                    conn.sendall(command_with_flag + b"\r\n" + encrypted_message + b"\r\n" + encrypted_signed_data)
                
                print(f"Message encrypted with session key and sent to {self.ip}")
            else:
                # Handle unencrypted message with signed data
                if filename:
                    conn.sendall(command + b"\r\n" + filename + b"\r\n" + message + b"\r\n" + signed_data)
                else:
                    if signed_data:
                        conn.sendall(command + b"\r\n" + message + b"\r\n" + signed_data)
                    else:
                        conn.sendall(command + b"\r\n" + message + b"\r\n" + self.key_manager.sign_message(message))
        except Exception as e:
            print(f"Failed to send command {command} to peer {self.ip}:{self.port}: {e}")
        finally:
            if conn:
                conn.close()
        
    def __str__(self):
        return f"PeerInfo(Name={self.name}, Display Name={self.display_name} ip={self.ip}, port={self.port})"

class DHKESession:
    def __init__(self, key_manager, peer_ip):
        print(f"Initializing DHKE session for peer {peer_ip}")
        self.key_manager = key_manager
        self.peer_ip = peer_ip
        self.parameters = None  # Start with None, will be set later
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None
        print(f"Successfully initialized DHKE session object for peer {peer_ip}")
    
    def initialize(self):
        try:
            # If parameters haven't been set yet, get the global parameters
            if self.parameters is None:
                print("No parameters set, getting global DH parameters")
                self.parameters = get_dh_parameters()
            else:
                print("Using provided DH parameters")
                
            print("Generating ephemeral DH key pair")
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()
            print("Successfully generated ephemeral DH key pair")
        except Exception as e:
            print(f"Failed to initialize DHKE session: {e}")
            raise
    
    def get_public_key_and_signature(self):
        try:
            print("Getting public key and signature")
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Log the key being signed
            print(f"Signing DH public key of length: {len(public_key_bytes)}")
            print(f"First 20 bytes of DH key to sign: {public_key_bytes[:20]}")
            
            # Use a consistent salt length for compatibility
            signature = self.key_manager.private_key.sign(
                public_key_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32  # Fixed salt length for consistency
                ),
                hashes.SHA256()
            )
            
            print(f"Generated signature of length: {len(signature)}")
            print(f"First 20 bytes of signature: {signature[:20]}")
            
            print("Successfully got public key and signature")
            return public_key_bytes, signature
        except Exception as e:
            print(f"Failed to get public key and signature: {e}")
            raise
    
    def process_peer_key(self, peer_public_key_bytes, signature, peer_rsa_public_key):
        try:
            print("Processing peer's public key")
            if not verify_dh_public_key(peer_rsa_public_key, peer_public_key_bytes, signature):
                raise Exception("Invalid signature for DH public key")
            
            self.peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
            self.session_key = generate_shared_key(self.private_key, self.peer_public_key)
            print("Successfully processed peer's public key and generated session key")
            return self.session_key
        except Exception as e:
            print(f"Failed to process peer's public key: {e}")
            raise

class PeerConnectionListener(ServiceListener):
    def __init__(self, local_ip, service_name, key_manager: KeyManager):
        self.local_ip = local_ip
        self.service_name = service_name
        self.key_manager = key_manager

        self._internal_peers = {}
        self.peers = {}

        self.peers_lock = threading.Lock()

    def add_service(self, zeroconf, type, name):
        self.peers_lock.acquire()
        try:
            info = zeroconf.get_service_info(type, name)
            if info:
                peer_ip = socket.inet_ntoa(info.addresses[0])
                peer_port = info.port
                # Ignore self-discovery
                if peer_ip != self.local_ip or name != self.service_name:
                    peer_info = PeerInfo(name, peer_ip, peer_port, info.properties, self.key_manager)
                    # Check if the peer is already in the list
                    existing_peer = self.peers.get(peer_ip)
                    if existing_peer:
                        # Grab the public key from the existing peer
                        peer_info.public_key = existing_peer.public_key
                        print(f"Peer updated: {peer_info}")
                    self._internal_peers.update({name: peer_info})
                    self.peers.update({peer_ip: peer_info})
                    print(f"Peer added: {peer_info}")
                    
                    # Start authentication in a separate thread to avoid blocking
                    threading.Thread(target=self.authenticate_to_peer, args=(peer_info,)).start()
        finally:
            self.peers_lock.release()
            
    def authenticate_to_peer(self, peer_info):
        """Attempt to authenticate to a peer with retries"""
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                print(f"Authenticating to peer {peer_info.ip} (attempt {attempt+1}/{max_retries})")
                peer_info.authenticate_self_to_peer()
                # Add a small delay to allow the peer to process our authentication
                time.sleep(1)
                
                # If we authenticated but didn't get a public key, request it explicitly
                if not peer_info.public_key:
                    print(f"No public key received from {peer_info.ip}, requesting authentication")
                    self.request_authentication(peer_info)
                
                # If we now have a public key, we're good
                if peer_info.public_key:
                    print(f"Successfully authenticated with peer {peer_info.ip}")
                    return
                    
                # If we still don't have a public key, try again
                print(f"Authentication attempt {attempt+1} with {peer_info.ip} incomplete, retrying in {retry_delay}s")
                time.sleep(retry_delay)
            except Exception as e:
                print(f"Authentication attempt {attempt+1} with {peer_info.ip} failed: {e}")
                time.sleep(retry_delay)
        
        print(f"Failed to authenticate with peer {peer_info.ip} after {max_retries} attempts")
    
    def request_authentication(self, peer_info):
        """Request authentication from a peer that hasn't authenticated to us yet"""
        return peer_info.request_authentication_from_peer()

    def set_peer_public_key(self, peer_ip, public_key):
        self.peers_lock.acquire()
        try:
            peer = self.peers.get(peer_ip)
            if peer:
                peer.public_key = public_key
        finally:
            self.peers_lock.release()

    """def connect_to_peer(self, peer_ip, peer_port):
        try:
            conn = socket.create_connection((peer_ip, peer_port))
            handle_client(conn, (peer_ip, peer_port), self.private_key, self.public_key)
            # Request file list from the peer
            file_list = request_file_list(peer_ip, peer_port)
            print(f"Files available from {peer_ip}:{peer_port}: {file_list}")
            # Example: Request a specific file from the peer
            if file_list:
                request_file(peer_ip, peer_port, file_list[0])
        except Exception as e:
            print(f"Failed to connect to peer {peer_ip}:{peer_port}: {e}")
        """
     
    def remove_service(self, zeroconf, type, name):
        self.peers_lock.acquire()
        try:
            peer = self._internal_peers.pop(name, None)
            if peer:
                peer_ip = peer.ip
                result = self.peers.pop(peer_ip, None)
                if result:
                    print(f"Peer removed: {name}")
        finally:
            self.peers_lock.release()

    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        peer_ip = socket.inet_ntoa(info.addresses[0])
        peer_port = info.port
        peer = self.peers.get(peer_ip)
        if peer:
            peer.ip = peer_ip
            peer.port = peer_port
            peer.properties = info.properties
            print(f"Peer updated: {name}")