import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- Helper Functions ---
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def rsa_encrypt(public_key, plaintext):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def hash_gen(file_content):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    hash_digest = digest.finalize()
    return hash_digest

def signature_gen(private_key, hash_digest):
    signature = private_key.sign(
        hash_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature

# --- Client Code ---
def client(file_path):
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 6000

    # Generate client's RSA key pair
    client_private_key, client_public_key = generate_rsa_key_pair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"Client: Connected to server ({SERVER_HOST}, {SERVER_PORT})")

        # Receive server public key
        server_public_key_bytes = client_socket.recv(4096)
        server_public_key = deserialize_public_key(server_public_key_bytes)

        # Generate and send encrypted symmetric key
        symmetric_key = os.urandom(32)
        encrypted_symmetric_key = rsa_encrypt(server_public_key, symmetric_key)
        client_socket.sendall(encrypted_symmetric_key)

        # Read file content
        file_name = os.path.basename(file_path)
        file_name_bytes = file_name.encode()
        file_name_length = len(file_name_bytes).to_bytes(4, 'big')
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Compute hash of file content
        file_hash = hash_gen(file_content)

        # Sign the hash with client's private key
        signature = signature_gen(client_private_key, file_hash)

        # Serialize client's public key
        client_public_key_bytes = serialize_public_key(client_public_key)

        # Prepare data with public key, signature, filename, and content
        public_key_len = len(client_public_key_bytes).to_bytes(4, 'big')
        signature_len = len(signature).to_bytes(4, 'big')
        plaintext_data = (
            public_key_len +
            client_public_key_bytes +
            signature_len +
            signature +
            file_name_length +
            file_name_bytes +
            file_content
        )

        # Encrypt and send data
        encrypted_data = aes_encrypt(symmetric_key, plaintext_data)
        client_socket.sendall(encrypted_data)
        print(f"{' ' * 20}>> Client: File '{file_name}' uploaded successfully.")

# --- Entry Point ---
if __name__ == "__main__":
    file_path = input("Enter the file name (add path if necessary): ").strip()
    client(file_path)
