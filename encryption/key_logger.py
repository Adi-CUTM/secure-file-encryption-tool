import os
import json
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Encrypt AES key using RSA public key
def encrypt_key_for_log(aes_key, public_key_path=r"E:\Saved Games\secure_file_encryption\keys\rsa_public.pem"):
    with open(public_key_path, "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode()  
# Save log with encrypted AES key
def log_encryption_json(file_path, encryption_type, aes_key, log_file="logs/encryption_log.json"):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    encrypted_key_b64 = encrypt_key_for_log(aes_key)
    file_name = os.path.basename(file_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "timestamp": timestamp,
        "file_name": file_name,
        "encryption_type": encryption_type,
        "encrypted_key": encrypted_key_b64
    }

    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            data = json.load(f)
    else:
        data = []

    data.append(entry)

    with open(log_file, 'w') as f:
        json.dump(data, f, indent=4)
