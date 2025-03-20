import socket
import threading
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

# Configuration
SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "ClientB._p2pfileshare._tcp.local."
PORT = 5001

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

# Register the service using mDNS
def register_service():
    local_ip = get_local_ip()
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(local_ip)],
        port=PORT,
        properties={"description": "Client B"},
    )
    zeroconf = Zeroconf()
    zeroconf.register_service(info)
    print(f"Client B registered as {SERVICE_NAME} at {local_ip}:{PORT}")
    return zeroconf

# Handle incoming connections
def handle_client(conn, addr):
    print(f"Connected to {addr}")
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        print(f"Received from {addr}: {data}")
    conn.close()

# Start server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))  # Bind to all available interfaces
    server.listen()
    print(f"Server started on port {PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

# Listener to handle discovered services
class MyListener(ServiceListener):
    def __init__(self, local_ip, service_name):
        self.local_ip = local_ip
        self.service_name = service_name

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            peer_ip = socket.inet_ntoa(info.addresses[0])
            # Ignore self-discovery
            if peer_ip != self.local_ip and name != self.service_name:
                print(f"Discovered service: {name}")
                print(f"Address: {peer_ip}")
                print(f"Port: {info.port}")
                print(f"Properties: {info.properties}")

    def remove_service(self, zeroconf, type, name):
        print(f"Service removed: {name}")

    def update_service(self, zeroconf, type, name):
        print(f"Service updated: {name}")

# Discover peers using mDNS
def discover_peers(local_ip, service_name):
    zeroconf = Zeroconf()
    listener = MyListener(local_ip, service_name)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    print("Discovering peers...")
    return zeroconf, browser

# Main function
if __name__ == "__main__":
    zeroconf = None
    try:
        # Get local IP and service name
        local_ip = get_local_ip()
        # Register this client as a service
        zeroconf = register_service()
        # Start the server to accept connections
        threading.Thread(target=start_server).start()
        # Discover other peers
        discover_peers(local_ip, SERVICE_NAME)
        input("Press Enter to exit...\n")
    except KeyboardInterrupt:
        print("Shutting down Client B...")
    finally:
        if zeroconf:
            zeroconf.close()