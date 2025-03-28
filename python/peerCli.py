import cmd

from peerDiscovery import PeerConnectionListener
from peerKeys import KeyManager, initialize_client_keys, serialize_public_key
from peerFiles import remove_shared_file, add_shared_file, get_shared_files

class CliManager(cmd.Cmd):
    def __init__(self, peer_listener: PeerConnectionListener, key_manager: KeyManager):
        super().__init__()
        self.peer_listener: PeerConnectionListener = peer_listener
        self.key_manager: KeyManager = key_manager

        self.is_interrupted = False

        self.prompt = "(Command) > "
        self.intro = "Welcome to the P2P client. Type 'help' for a list of commands."

    def default(self, line):
        """Handle unrecognized commands"""
        if not self.is_interrupted:
            print(f"Unknown command: {line}. Type 'help' for a list of commands.")

    def do_renew_keys(self, line):
        """Renew the client's public and private keys and notify all connected peers"""
        private_key, public_key = initialize_client_keys(renew=True)
        # Notify peers of the new public key
        serialized_public_key = serialize_public_key(public_key)
        for peer in self.peer_listener.peers.values():
            peer.send_command(b"RENEW KEYS", serialized_public_key)
        # Set the new keys
        self.key_manager.set_new_keys(private_key, public_key)
        print("Keys renewed.")

    def do_request(self, line):
        """Request to download a shared file from an available peer.
        request <file_hash>"""
        pass

    def do_send(self, line):
        """Send a shared file to a given peer.
        send <peer_display_name> <filename>"""
        pass

    def do_list_shared_files(self, line):
        """List all shared files"""
        shared_files = get_shared_files()
        if len(shared_files) == 0:
            print("No files shared.")
            return
        print("Shared files:")
        for file in get_shared_files():
            print(file)

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