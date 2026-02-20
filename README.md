# Secure File Transfer System using Elliptic Curve Cryptography (ECC)

## 📌 Project Overview

This project implements a secure file transfer system using **Hybrid Cryptography** combining Elliptic Curve Cryptography (ECC) and Symmetric Encryption.

The system ensures:

- 🔐 Confidentiality
- 🛡 Integrity
- 👤 Authentication
- 🔁 Forward Secrecy
- 🚫 Tamper Detection

This project demonstrates practical implementation of modern cryptographic protocols used in real-world secure communication systems.

---

## 🏗 System Architecture

The system follows a hybrid encryption model:

1. **ECDH (Elliptic Curve Diffie-Hellman)**  
   - Secure shared key exchange between sender and receiver  
   - Curve Used: `SECP256R1`

2. **HKDF (HMAC-based Key Derivation Function)**  
   - Derives a strong 256-bit AES key from shared secret  

3. **AES-256-GCM**  
   - Encrypts file data  
   - Provides confidentiality + built-in integrity verification  

4. **ECDSA (Elliptic Curve Digital Signature Algorithm)**  
   - Ensures sender authenticity  
   - Prevents signature forgery  

---

## 🔐 Cryptographic Flow
Sender (Alice) Receiver (Bob)

Generate ECC Keys Generate ECC Keys
| |
|------ Public Key Exchange ----|
| |
Compute Shared Secret Compute Shared Secret
| |
Derive AES Key (HKDF) Derive AES Key (HKDF)
| |
Encrypt File (AES-GCM) --> Decrypt File (AES-GCM)
Sign Ciphertext (ECDSA) --> Verify Signature


---

## 🚀 Features

- Secure ECC key generation
- ECDH shared secret derivation
- AES-256-GCM authenticated encryption
- ECDSA digital signatures
- Tamper detection validation
- Attack simulation testing
- Modular crypto architecture
- Git-based version control

---

## 🧪 Security Validation

The system was tested against:

### 1️⃣ Ciphertext Tampering
- Modified encrypted data
- Result: `InvalidTag` exception
- ✔ Integrity successfully enforced

### 2️⃣ Signature Tampering
- Modified signed data
- Result: `InvalidSignature` exception
- ✔ Authentication successfully enforced

### 3️⃣ Wrong Public Key Verification
- Attempted verification with invalid public key
- ✔ Signature verification failed

---

## 📂 Project Structure
secure-file-transfer/
│
├── crypto_core/
│ ├── ecc.py
│ ├── key_derivation.py
│ ├── encryption.py
│ ├── signature.py
│
├── demo.py
├── requirements.txt
├── README.md
└── .gitignore


---

## 🛠 Technologies Used

- Python 3
- cryptography library
- Elliptic Curve Cryptography (SECP256R1)
- AES-256-GCM
- HKDF
- Git & GitHub

---

## 🔍 Security Properties Achieved

| Security Property | Implementation |
|-------------------|---------------|
| Confidentiality | AES-256-GCM |
| Integrity | GCM Authentication Tag |
| Authentication | ECDSA |
| Forward Secrecy | ECDH |
| Tamper Detection | Built-in GCM + Signature Validation |

---

## 📈 Real-World Relevance

This architecture mirrors cryptographic principles used in:

- TLS/SSL secure communication
- Secure file storage systems
- End-to-end encrypted messaging platforms
- Secure cloud file sharing services

---

## 🔮 Future Enhancements

- FastAPI backend integration
- User authentication system
- Encrypted file storage service
- Database key management
- Secure REST APIs
- Deployment using Docker
- Web interface for file upload/download

---

## 👩‍💻 Author

**Sowmya Dasari**  
