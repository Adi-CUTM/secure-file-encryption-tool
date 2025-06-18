import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def recover_aes_key_from_log(file_name, rsa_private_key_path, log_path="logs/encryption_log.json"):
    # Load RSA Private Key
    with open(rsa_private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Load log file
    with open(log_path, 'r') as f:
        logs = json.load(f)

    # Search for the specified file
    for entry in logs:
        if entry["file_name"] == file_name and "encrypted_key" in entry:
            encrypted_key_b64 = entry["encrypted_key"]
            encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
            try:
                decrypted_key = cipher_rsa.decrypt(encrypted_key_bytes)
                print(f"[✓] Recovered AES Key for '{file_name}':\n{decrypted_key.decode()}")
                return decrypted_key.decode()
            except Exception as e:
                print("[✗] Error decrypting AES key:", e)
                return None

    print("[!] No encrypted key found for this file.")
    return None


# Example usage
if __name__ == "__main__":
    file_name = input("Enter the encrypted file name (e.g., README.md.enc): ")
    rsa_private_key_path = input("Enter path to your RSA private key (e.g., keys/private.pem): ")
    recover_aes_key_from_log(file_name, rsa_private_key_path)
