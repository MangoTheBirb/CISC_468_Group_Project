from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

KEY_FILES_DIR = "keys"

class KeyManager():
    def __init__(self):
        self.private_key, self.public_key = initialize_client_keys()

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