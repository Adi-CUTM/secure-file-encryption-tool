# 🛡️ Secure File Encryption Tool

A robust GUI-based application built with **Tkinter** that allows users to securely encrypt and decrypt files using **AES (symmetric)** or **RSA (asymmetric)** encryption. The tool ensures secure file management, logs encryption activity, and offers key recovery via RSA protection of AES keys.

---

## 📁 Project Structure

```
SecureFileEncryptionTool/
├── encryption/
│   ├── __init__.py
│   ├── aes_utils.py         # AES encryption and decryption logic
│   ├── rsa_utils.py         # RSA encryption and decryption logic
│   ├── key_logger.py        # AES key logger using RSA encryption
│
├── gui/
│   ├── __init__.py
│   └── main_gui.py          # Main Tkinter GUI interface
│
├── keys/
│   ├── rsa_private.pem      # RSA private key (for decryption)
│   ├── rsa_public.pem       # RSA public key (for encrypting AES keys)
│   └── recover_aes_key.py   # CLI script to recover AES keys from log
│
├── logs/
│   └── encryption_log.json  # JSON log of encrypted files and AES keys
│
├── .gitignore               # Files and folders to ignore in Git
└── README.md                # Project documentation
```

---

## ⚙️ Features

✅ **AES Encryption (CBC mode)**  
✅ **RSA Encryption for files**  
✅ **AES key encryption using RSA**  
✅ **Key masking + storage in JSON log**  
✅ **Key recovery CLI for admins**  
✅ **Auto file deletion post encryption/decryption**  
✅ **Tkinter-based GUI**

---

## 🧪 AES Key Testing Samples

- **16-bit**: `aB3xT7pLq9ZrU2Nm`  
- **24-bit**: `Bf9rEt7Lq9ZrU2NmAx7Lq3nP`  
- **32-bit**: `Xf9rEt7Lq9ZrU2NmAx7Lq3nPWa9zSkDm`

---

## 🚀 Getting Started

### 🔧 Prerequisites

Install required libraries:

```bash
pip install pycryptodome
```

---

## 🖥️ Run the Application

```bash
python gui/main_gui.py

python -m gui.main_gui
```

---

## 🔐 Recover a Forgotten AES Key

If a user forgets the AES key:

1. Open terminal and run:

   ```bash
   python keys/recover_aes_key.py
   ```

2. Enter the filename shown in `logs/encryption_log.json`
3. The original AES key will be decrypted using your private RSA key.

---

## 🧾 Encryption Log Format

Each log entry in `logs/encryption_log.json` contains:

```json
{
    "timestamp": "2025-06-18 10:55:03",
    "file_name": "README.md.enc",
    "encryption_type": "AES",
    "encrypted_key": "<RSA_ENCRYPTED_AES_KEY>"
}
```

---

## 📌 .gitignore Highlights

- `logs/` → prevent logging sensitive encryption history  
- `keys/private.pem` → hide private keys  
- `__pycache__/` and other build cache files  
- `.env`, IDE, and system files
-  you have to create the log file and give the appropriate path when run the project
-  you have to create two file named in the structure as well and make sure not to visible any one

---

## 📄 License

This project is developed for **educational purposes** only. Unauthorized use for malicious purposes is strictly discouraged.
