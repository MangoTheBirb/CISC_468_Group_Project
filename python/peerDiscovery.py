from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener
import os
import socket
import threading

from peerKeys import serialize_public_key, KeyManager

SERVICE_TYPE = "_p2pfileshare._tcp.local."

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

class PeerInfo():
    def __init__(self, name, ip, port, properties, key_manager: KeyManager):
        self.name = name
        self.ip = ip
        self.port = port
        self.properties = properties
        self.public_key = None
        self.display_name = properties.get(b"display_name", b"").decode("utf-8")
        self.key_manager = key_manager

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

    def send_command(self, command, filename=None, message=None):
        conn = None
        print(f"Sending command {command} to peer {self.ip}:{self.port}")
        print(f"Message: {message}")
        print(f"Filename: {filename}")
    
        try:
            signed_message = self.key_manager.sign_message(message)
            conn = socket.create_connection((self.ip, self.port))
            conn.sendall(command + b"\r\n" + filename + b"\r\n" +  message + b"\r\n" + signed_message)
        except Exception as e:
            print(f"Failed to send command {command} to peer {self.ip}:{self.port}: {e}")
        finally:
            if conn:
                conn.close()
        
    def __str__(self):
        return f"PeerInfo(Name={self.name}, Display Name={self.display_name} ip={self.ip}, port={self.port})"

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
                    print(f"Peer added: {peer_info}")
                    self._internal_peers.update({name: peer_info})
                    self.peers.update({peer_ip: peer_info})
                    # Connect to the discovered peer
                    peer_info.authenticate_self_to_peer()
                    #threading.Thread(target=self.connect_to_peer, args=(peer_ip, peer_port)).start()
        finally:
            self.peers_lock.release()

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