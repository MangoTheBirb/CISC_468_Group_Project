# python_client.py

import socket
import threading
import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PEER_DISCOVERY_PORT = 9999
FILE_TRANSFER_PORT = 10000
SHARED_FOLDER = "./shared_files"
ENCRYPTION_KEY = os.urandom(32)  # For file encryption

# Generate RSA keys for mutual authentication
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_keys()

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def encrypt_message(message, recipient_pub_key):
    return recipient_pub_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_message(ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def peer_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PEER_DISCOVERY_PORT))

    print("[*] Listening for peers...")
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"[*] Discovered peer: {addr} says {data.decode()}")

def discover_broadcast():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = "Hello from Python Client!"
    sock.sendto(message.encode(), ('<broadcast>', PEER_DISCOVERY_PORT))

def handle_file_request(conn):
    data = conn.recv(4096)
    request = json.loads(data.decode())

    if request['action'] == 'LIST_FILES':
        files = os.listdir(SHARED_FOLDER)
        conn.send(json.dumps(files).encode())
    elif request['action'] == 'REQUEST_FILE':
        filename = request['filename']
        filepath = os.path.join(SHARED_FOLDER, filename)
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                file_data = f.read()

            # Encrypt the file before sending (AES symmetric encryption)
            cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CFB8(ENCRYPTION_KEY[:16]), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_file = encryptor.update(file_data) + encryptor.finalize()

            conn.sendall(encrypted_file)
        else:
            conn.send(b'File not found!')

def start_file_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', FILE_TRANSFER_PORT))
    sock.listen(5)

    print("[*] File server started...")
    while True:
        conn, addr = sock.accept()
        print(f"[*] Connection from {addr}")
        threading.Thread(target=handle_file_request, args=(conn,)).start()

if __name__ == "__main__":
    threading.Thread(target=peer_discovery).start()
    threading.Thread(target=start_file_server).start()

    while True:
        cmd = input("Enter command (discover/list/request): ").strip()
        if cmd == "discover":
            discover_broadcast()
        elif cmd == "list":
            # simulate listing files from a peer (use Go client IP)
            pass
        elif cmd == "request":
            # simulate requesting file from Go client
            pass
