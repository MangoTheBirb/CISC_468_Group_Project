from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEY_FILES_DIR = "keys"

class KeyManager:
    def __init__(self):
        self.private_key, self.public_key = initialize_client_keys()
        self.dh_params = None
        self.sessions = {}  # Store session keys by peer IP

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

    def initialize_dh(self):
        self.dh_params = DHParameters()
        return self.dh_params.get_public_bytes()

    def create_session(self, peer_ip, peer_dh_public):
        if not self.dh_params:
            raise Exception("DH parameters not initialized")
        session_key = self.dh_params.compute_shared_key(peer_dh_public)
        self.sessions[peer_ip] = SessionKey(session_key)
        self.dh_params = None  # Clear DH parameters after use
        return self.sessions[peer_ip]

    def get_session(self, peer_ip):
        return self.sessions.get(peer_ip)

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

class DHParameters:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_key(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        # Derive session key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

class SessionKey:
    def __init__(self, key):
        self.key = key
        self.iv = os.urandom(16)
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        # Add PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return self.iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data):
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return unpadder.update(decrypted) + unpadder.finalize()