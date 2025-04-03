import socket
import threading

PEER_DISCOVERY_PORT = 9999
SHARED_FOLDER = "./shared_files"

def discover_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = "Hello from Python Client!"
    sock.sendto(message.encode(), ('<broadcast>', PEER_DISCOVERY_PORT))

def discover_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PEER_DISCOVERY_PORT))

    print("[*] Listening for peers...")
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"[*] Discovered peer: {addr} says {data.decode()}")

if __name__ == "__main__":
    threading.Thread(target=discover_server).start()

    while True:
        cmd = input("Enter command (discover/list/request): ").strip()
        if cmd == "discover":
            discover_client()
        elif cmd == "list":
            # simulate listing files from a peer (use Go client IP)
            pass
        elif cmd == "request":
            # simulate requesting file from Go client
            pass