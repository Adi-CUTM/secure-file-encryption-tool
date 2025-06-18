from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# Padding functions
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding detected.")
    return data[:-pad_len]

# AES Encryption
def encrypt_file_aes(file_path, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes.")

    with open(file_path, 'rb') as f:
        data = f.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)

    enc_file = file_path + '.enc'
    with open(enc_file, 'wb') as f:
        f.write(iv + encrypted_data)

    os.remove(file_path)  # Delete original file after encryption
    return enc_file

# AES Decryption
def decrypt_file_aes(file_path, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes.")

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)
    original_data = unpad(decrypted_padded)

    dec_file = file_path.replace('.enc', '.dec')
    with open(dec_file, 'wb') as f:
        f.write(original_data)

    os.remove(file_path)  # Delete encrypted file after decryption
    return dec_file
