

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

KEY_DIR = r"E:\Saved Games\secure_file_encryption\keys"
os.makedirs(KEY_DIR, exist_ok=True)

PUBLIC_KEY_PATH = os.path.join(KEY_DIR, r"E:\Saved Games\secure_file_encryption\keys\rsa_public.pem")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, r"E:\Saved Games\secure_file_encryption\keys\rsa_private.pem")

def generate_keys():
    if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key)
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key)

def encrypt_file_rsa(file_path):
    generate_keys()
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_key = RSA.import_key(f.read())

    rsa_cipher = PKCS1_OAEP.new(public_key)

    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    with open(file_path, 'rb') as f:
        data = f.read()
    padding_len = 16 - len(data) % 16
    data += bytes([padding_len]) * padding_len

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = aes_cipher.encrypt(data)

    out_file = file_path + '.rsa'
    with open(out_file, 'wb') as f:
        f.write(len(encrypted_key).to_bytes(2, 'big'))
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)

    os.remove(file_path)  # Delete original
    return out_file

def decrypt_file_rsa(file_path):
    generate_keys()
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = RSA.import_key(f.read())

    rsa_cipher = PKCS1_OAEP.new(private_key)

    with open(file_path, 'rb') as f:
        encrypted_key_len = int.from_bytes(f.read(2), 'big')
        encrypted_key = f.read(encrypted_key_len)
        iv = f.read(16)
        encrypted_data = f.read()

    aes_key = rsa_cipher.decrypt(encrypted_key)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = aes_cipher.decrypt(encrypted_data)
    padding_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_len]

    out_file = file_path.replace(".rsa", ".dec")
    with open(out_file, 'wb') as f:
        f.write(decrypted_data)

    os.remove(file_path)  # Delete encrypted
    return out_file
