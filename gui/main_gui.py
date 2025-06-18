import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import json
from datetime import datetime
from encryption.aes_utils import encrypt_file_aes, decrypt_file_aes
from encryption.rsa_utils import encrypt_file_rsa, decrypt_file_rsa
from encryption.key_logger import log_encryption_json  # Use the updated logger with RSA-encrypted AES key

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        self.root.geometry("600x400")
        self.root.configure(bg="black")

        self.selected_file = None

        tk.Label(root, text="Secure File Encryption Tool", font=("Helvetica", 18, "bold"),
                 bg="black", fg="white").pack(pady=20)

        tk.Button(root, text="Select File", command=self.select_file,
                  bg="grey", fg="white", width=20).pack(pady=10)

        tk.Button(root, text="Encrypt with AES", command=self.encrypt_aes,
                  bg="blue", fg="white", width=20).pack(pady=5)

        tk.Button(root, text="Decrypt with AES", command=self.decrypt_aes,
                  bg="blue", fg="white", width=20).pack(pady=5)

        tk.Button(root, text="Encrypt with RSA", command=self.encrypt_rsa,
                  bg="green", fg="white", width=20).pack(pady=5)

        tk.Button(root, text="Decrypt with RSA", command=self.decrypt_rsa,
                  bg="green", fg="white", width=20).pack(pady=5)

        self.status = tk.Label(root, text="No file selected", bg="black", fg="white")
        self.status.pack(pady=20)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            self.status.config(text=f"Selected: {os.path.basename(file_path)}")

    def encrypt_aes(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No file selected")
            return
        key = simpledialog.askstring("AES Key", "Enter 16/24/32-character AES key:")
        if not key or len(key) not in [16, 24, 32]:
            messagebox.showerror("Invalid Key", "Key must be 16, 24, or 32 characters long.")
            return
        try:
            key_bytes = key.encode()
            output_file = encrypt_file_aes(self.selected_file, key_bytes)
            log_encryption_json(output_file, "AES", key_bytes)  # Log with RSA encrypted key
            self.selected_file = output_file
            self.status.config(text=f"Encrypted: {os.path.basename(output_file)}")
            messagebox.showinfo("Success", f"Encrypted and original file removed: {os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_aes(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No file selected")
            return
        key = simpledialog.askstring("AES Key", "Enter 16/24/32-character AES key:")
        if not key or len(key) not in [16, 24, 32]:
            messagebox.showerror("Invalid Key", "Key must be 16, 24, or 32 characters long.")
            return
        try:
            output_file = decrypt_file_aes(self.selected_file, key.encode())
            self.selected_file = output_file
            self.status.config(text=f"Decrypted: {os.path.basename(output_file)}")
            messagebox.showinfo("Success", f"Decrypted and encrypted file removed: {os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def encrypt_rsa(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No file selected")
            return
        try:
            output_file = encrypt_file_rsa(self.selected_file)
            log_encryption_json(output_file, "RSA", b"RSA_PUBLIC_KEY")  # Dummy key entry for RSA
            self.selected_file = output_file
            self.status.config(text=f"Encrypted: {os.path.basename(output_file)}")
            messagebox.showinfo("Success", f"Encrypted and original file removed: {os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("RSA Encryption Error", str(e))

    def decrypt_rsa(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No file selected")
            return
        try:
            output_file = decrypt_file_rsa(self.selected_file)
            self.selected_file = output_file
            self.status.config(text=f"Decrypted: {os.path.basename(output_file)}")
            messagebox.showinfo("Success", f"Decrypted and encrypted file removed: {os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("RSA Decryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
