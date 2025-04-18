import cmd
import os
import threading
import sys
from peerDiscovery import PeerConnectionListener
from peerKeys import KeyManager, initialize_client_keys, serialize_public_key
from peerFiles import remove_shared_file, add_shared_file, get_shared_files, decrypt_file_AES
from Crypto.Cipher import AES

SHARED_FILES_DIR = "shared_files"

class CliManager(cmd.Cmd):
    def __init__(self, peer_listener: PeerConnectionListener, key_manager: KeyManager):
        super().__init__()
        self.peer_listener: PeerConnectionListener = peer_listener
        self.key_manager: KeyManager = key_manager

        self.is_interrupted = False

        self.prompt = "(Command) > "
        self.intro = "Welcome to the P2P client. Type 'help' for a list of commands."
        
        # Set empty_line_behavior to prevent automatic re-execution of last command
        self.empty_line_behavior = False
    
    # Override the empty_line method to do nothing
    def emptyline(self):
        pass
        
    # Override onecmd to control behavior
    def onecmd(self, line):
        """Override the onecmd method to handle commands without auto-execution"""
        try:
            return super().onecmd(line)
        except Exception as e:
            print(f"Error executing command: {e}")
            return False

    def default(self, line):
        """Handle unrecognized commands"""
        if not self.is_interrupted:
            print(f"Unknown command: {line}. Type 'help' for a list of commands.")

    def do_renew_keys(self, line):
        """Renew the client's public and private keys and notify all connected peers"""
        private_key, public_key = initialize_client_keys(renew=True)
        # Notify peers of the new public key
        serialized_public_key = serialize_public_key(public_key)
        # Sign the new public key with the old private key before updating
        signed_key = self.key_manager.sign_message(serialized_public_key)
        
        # Set the new keys
        self.key_manager.set_new_keys(private_key, public_key)
        
        # Send to all peers
        for peer in self.peer_listener.peers.values():
            peer.send_command(b"RENEW KEYS", serialized_public_key, signed_key)
            
        print("Keys renewed.")

    def do_request_file(self, line):
        """Request to download a shared file from an available peer.
        request <file_hash>"""
        #split the line into parts
        #find peer in the peer list
        #send the request to the peer

        print(line)
        parts = line.strip().split()
        if len(parts) != 2:
            print("Usage: request_file <peer_display_name> <filename>")
            return
        peer_display_name = parts[0]
        filename = parts[1]
        # Find the peer in the peer list
        peer = None
        for p in self.peer_listener.peers.values():
            if p.display_name == peer_display_name:
                peer = p
                break
        
        if peer is None:
            print(f"Peer {peer_display_name} not found.")
            return
        
        # Encode the filename and sign it
        filename_encoded = filename.encode()
        signed_filename = self.key_manager.sign_message(filename_encoded)
        
        #Send the request to the peer
        peer.send_command(b"REQUEST_FILE", filename_encoded, signed_filename)

    def do_send_file(self, line):
        """Send a shared file to a given peer.
        send <peer_display_name> <filename>"""
        print("line: ", line)
        parts = line.strip().split()
        if len(parts) != 2:
            print("Usage: send_file <peer_display_name> <filename>")
            return

        peer_display_name = parts[0]
        filename = parts[1]
        
        # Find the peer in the peer list
        peer = None
        for p in self.peer_listener.peers.values():
            if p.display_name == peer_display_name:
                peer = p
                break
                
        if peer is None: 
            print(f"Peer {peer_display_name} not found.")
            return  
            
        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist.")
            return
            
        try:
            # Get the AES key for this file
            key = self.key_manager.get_aes_key(filename)
            if not key:
                print(f"No encryption key found for {filename}")
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
            
            # Sign the file data
            signed_data = self.key_manager.sign_message(decrypted_data)
            
            # Send the decrypted file data to the peer
            peer.send_command(b"RECEIVE_FILE", decrypted_data, signed_data, filename.encode())
            print(f"Successfully sent decrypted file {filename} to {peer_display_name}")
        except Exception as e:
            print(f"Error sending file: {e}")
            # Clean up temporary file if it exists
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)

    def do_list_shared_files(self, line):
        """List all shared files"""
        shared_files = get_shared_files()
        if len(shared_files) == 0:
            print("No files shared.")
            return
        print("Shared files:")
        for file in get_shared_files():
            print(file)

    def do_send_file_list(self,line):
        """Send a list of all shared files to a given peer.
        send_file_list <peer_display_name>"""
        print("line: ", line)
        parts = line.strip().split()
        
        
        if len(parts) != 1:
            print("Usage: send_file_list <peer_display_name>")
            return
        
        peer_display_name = parts[0]

        files = get_shared_files()
        print(files)
        if len(files) == 0:
            print("No files in shared folder.")
            return
        
        # Find the peer in the peer list
        peer = None
        for p in self.peer_listener.peers.values():
            if p.display_name == peer_display_name:
                peer = p
                break
        
        if peer is None:
            print(f"Peer {peer_display_name} not found.")
            return
        
        # Send the list of files to the peer
        file_list = "\n".join(files).encode()
        # Sign the file list
        signed_file_list = self.key_manager.sign_message(file_list)
        peer.send_command(b"FILE_LIST_PRINT", file_list, signed_file_list)
    
    def do_request_file_list(self,line):
        """Get list of all shared files to a given peer.
        request_file_list <peer_display_name>"""
        print("line: ", line)
        parts = line.strip().split()
        
        
        if len(parts) != 1:
            print("Usage: send_file_list <peer_display_name>")
            return
        
        peer_display_name = parts[0]

        files = get_shared_files()
        print(files)
        if len(files) == 0:
            print("No files in shared folder.")
            return
        
        # Find the peer in the peer list
        peer = None
        for p in self.peer_listener.peers.values():
            if p.display_name == peer_display_name:
                peer = p
                break
        
        if peer is None:
            print(f"Peer {peer_display_name} not found.")
            return
        
        # Send the list of files to the peer
        file_list = "\n".join(files).encode()
        # Sign the file list
        signed_file_list = self.key_manager.sign_message(file_list)
        peer.send_command(b"FILE_LIST_REQUEST", file_list, signed_file_list)

    def do_add_shared_file(self, line):
        """Add a file to the shared directory and make it available to peers.
        add_shared_file <filepath>"""
        add_shared_file(line)

    def do_remove_shared_file(self, line):
        """Remove a shared file given its name and remove it from the shared directory.
        remove_shared_file <filename>
        Note: This will not delete the file from peers that have already received it."""
        remove_shared_file(line)

    def do_list_peers(self, line):
        """List all connected peers"""
        if len(self.peer_listener.peers) == 0:
            print("No peers connected.")
            return
        print("Connected peers:")
        for peer in self.peer_listener.peers.values():
            print(f"{peer.display_name} ({peer.ip})")

    


    def do_exit(self, arg):
        """Exit the P2P client"""
        return True