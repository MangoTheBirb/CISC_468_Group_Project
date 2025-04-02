import os

SHARED_FILES_DIR = "shared_files"

def initialize_shared_files():
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)

def get_shared_files():
    try:
        files = os.listdir(SHARED_FILES_DIR)
        return files
    except Exception as e:
        print(f"Error getting shared files: {e}")
        return []
    
def add_shared_file(filepath):
    if not os.path.exists(filepath):
        print(f"File: {filepath} does not exist.")
        return
    filename = os.path.basename(filepath)
    try:
        shared_filepath = os.path.join(SHARED_FILES_DIR, filename)
        with open(filepath, "rb") as f:
            with open(shared_filepath, "wb") as f_shared:
                f_shared.write(f.read())
        print(f"Added file: {filename}")
    except Exception as e:
        print(f"Error adding file: {filename}: {e}")
    pass

def remove_shared_file(filename):
    try:
        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File: {filename} does not exist and is not shared.")
            return
        os.remove(filepath)
        print(f"Removed file: {filename}")
    except Exception as e:
        print(f"Error deleting file: {filename}: {e}")

def send_file_to_peer(conn, filename):
    """Send a file to peer"""
    filepath = os.path.join(SHARED_FILES_DIR, filename)
    try:
        # Send file size first
        file_size = os.path.getsize(filepath)
        conn.sendall(f"{file_size}\n".encode())
        
        # Wait for ready signal
        if conn.recv(1024).decode().strip() != "READY":
            raise Exception("Peer not ready to receive")
            
        # Send file data in chunks
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
        
        # Wait for confirmation
        if conn.recv(1024).decode().strip() != "RECEIVED":
            raise Exception("File transfer not confirmed")
            
        print(f"Sent file {filename}")
    except Exception as e:
        print(f"Error sending file {filename}: {e}")
        conn.sendall(b"ERROR\n")

def receive_file_from_peer(conn, filename):
    """Receive a file from peer"""
    filepath = os.path.join(SHARED_FILES_DIR, filename)
    try:
        # Get file size
        size = int(conn.recv(1024).decode().strip())
        
        # Signal ready to receive
        conn.sendall(b"READY\n")
        
        # Receive file data
        received = 0
        with open(filepath, "wb") as f:
            while received < size:
                chunk = conn.recv(min(4096, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        
        # Confirm receipt
        conn.sendall(b"RECEIVED\n")
        print(f"Received file {filename}")
        return True
    except Exception as e:
        print(f"Error receiving file {filename}: {e}")
        return False