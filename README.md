# 🕶️ ShadoCrypt

> Ultimate Cybersecurity Toolkit for Encoding, Hashing & Symmetric Encryption — Powered by React + Express + Python

![image](https://github.com/user-attachments/assets/374f3043-e5b2-4ce3-ac03-bdf819a4966e)

---

## ⚡ About

**ShadoCrypt** is a multi-functional cryptographic web application designed for penetration testers, ethical hackers, and cybersecurity enthusiasts. It supports:

- 🔐 **Symmetric Encryption** (AES, DES, Blowfish, RC4, Twofish, etc.)
- 💥 **Hashing Algorithms** (MD5, SHA256, bcrypt, PBKDF2, etc.)
- 🎭 **Encoding Schemes** (Base64, Base32, ROT13, Hex, URL encoding)

All heavy cryptographic operations are securely handled by a **Python backend** via an **Express.js API**, while the frontend is built with **React + TailwindCSS** for a sleek UI.

---

## 🛠️ Tech Stack

- **Frontend**: React, TailwindCSS
- **Backend**: Express.js (Node.js) API
- **Crypto Core**: Python (using cryptography, pycryptodome, base58, etc.)

---

## 🚀 Features

### ✅ Symmetric Encryption

- AES, DES, RC4, RC5, RC6
- Blowfish, Twofish, ChaCha20, Rabbit

### ✅ Hashing Algorithms

- SHA-1, SHA-256, SHA-512, SHA3
- bcrypt, scrypt, PBKDF2, RIPEMD-160

### ✅ Encoding/Decoding

- Base64, Base32, Base58, ROT13, Hex, URL Encoding

---

## 📦 Installation

> ⚠️ Clone only — `node_modules/` and `build/` are excluded via `.gitignore`.

```bash
git clone https://github.com/amitsingh114/ShadoCrypt.git
cd ShadoCrypt
cd backend  
npm install
python3 -m venv venv
source venv/bin/activate # Activate the virtual environment
pip install cryptography pycryptodome bcrypt scrypt base32 pybase58
cd ../frontend # Go back one level, then into frontend
npm install
cd /home/rambo/ShadoCrypt/backend # Adjust path if different
source venv/bin/activate         # ACTIVATE THE PYTHON VENV!
node server.js
cd /home/rambo/ShadoCrypt/frontend # Adjust path if different
npm start
