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

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def hash_gen(file_content):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    return digest.finalize()

def verify_signature(public_key, signature, expected_digest):
    try:
        public_key.verify(
            signature,
            expected_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False

# --- Server Code ---
def server():
    HOST = '127.0.0.1'
    PORT = 6000
    UPLOAD_DIR = 'Upload'
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Generate server's RSA key pair
    server_private_key, server_public_key = generate_rsa_key_pair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"Server: Listening on {HOST}:{PORT}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Server: Connection accepted from {addr}")

            # Send server's public key
            server_public_key_bytes = serialize_public_key(server_public_key)
            conn.sendall(server_public_key_bytes)

            # Receive encrypted symmetric key
            encrypted_symmetric_key = conn.recv(256)
            symmetric_key = rsa_decrypt(server_private_key, encrypted_symmetric_key)

            # Receive and decrypt file data
            encrypted_data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                encrypted_data += chunk

            plaintext_data = aes_decrypt(symmetric_key, encrypted_data)

            # Parse public key
            offset = 0
            pk_len = int.from_bytes(plaintext_data[offset:offset+4], 'big')
            offset += 4
            client_public_key_bytes = plaintext_data[offset:offset+pk_len]
            offset += pk_len
            client_public_key = deserialize_public_key(client_public_key_bytes)

            # Parse signature
            sig_len = int.from_bytes(plaintext_data[offset:offset+4], 'big')
            offset += 4
            signature = plaintext_data[offset:offset+sig_len]
            offset += sig_len

            # Parse filename
            name_len = int.from_bytes(plaintext_data[offset:offset+4], 'big')
            offset += 4
            file_name = plaintext_data[offset:offset+name_len].decode()
            offset += name_len

            # Get file content
            file_content = plaintext_data[offset:]
            save_path = os.path.join(UPLOAD_DIR, file_name)

            with open(save_path, 'wb') as f:
                f.write(file_content)

            print(f"Server: File saved to '{save_path}'.")

            # Allow optional modification for tamper test
            input(">> You may now edit the file before verification. Press Enter when ready...")

            # Re-read file content after potential tampering
            with open(save_path, 'rb') as f:
                updated_content = f.read()

            # Generate new hash and verify
            new_hash = hash_gen(updated_content)
            verified = verify_signature(client_public_key, signature, new_hash)

            if verified:
                print("✅ Server: Signature verified. File is authentic and unmodified.")
            else:
                print("❌ Server: Signature verification failed. File may have been tampered with.")

# --- Entry Point ---
if __name__ == "__main__":
    server()
