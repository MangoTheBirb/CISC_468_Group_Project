from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

KEY_FILES_DIR = "keys"

class KeyManager():
    def __init__(self):
        self.private_key, self.public_key = initialize_client_keys()
        self.aes_keys = {}  # Dictionary to store AES keys for files
        self._load_aes_keys() # Load existing AES keys from file
        
    def set_new_keys(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def sign_message(self, message):
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def get_serialized_public_key(self):
        return serialize_public_key(self.public_key)

    def store_aes_key(self, filename, key):
        """Store AES key for a file"""
        self.aes_keys[filename] = key
        self._save_aes_keys()  # Persist keys to file

    def get_aes_key(self, filename):
        """Retrieve AES key for a file"""
        return self.aes_keys.get(filename)

    def _save_aes_keys(self):
        """Save AES keys to a file"""
        aes_keys_path = os.path.join(KEY_FILES_DIR, "aes_keys.txt")
        with open(aes_keys_path, "w") as f:
            for filename, key in self.aes_keys.items():
                f.write(f"{filename}:{key.hex()}\n")

    def _load_aes_keys(self):
        """Load AES keys from file"""
        aes_keys_path = os.path.join(KEY_FILES_DIR, "aes_keys.txt")
        if os.path.exists(aes_keys_path):
            with open(aes_keys_path, "r") as f:
                for line in f:
                    filename, key_hex = line.strip().split(":")
                    self.aes_keys[filename] = bytes.fromhex(key_hex)

def initialize_client_keys(renew=False):
    if not os.path.exists(KEY_FILES_DIR):
        os.makedirs(KEY_FILES_DIR)
    private_key_path = os.path.join(KEY_FILES_DIR, "private_key.pem")
    if os.path.exists(private_key_path) and not renew:
        with open(private_key_path, "rb") as f:
            private_key_bytes = f.read()
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
            public_key = private_key.public_key()
            return private_key, public_key
    else:
        private_key, public_key = generate_key_pair()
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key, public_key

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key to send over the network
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize public key received from the network
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)