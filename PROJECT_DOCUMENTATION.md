# PROJECT DOCUMENTATION: Zero-Trust Secure File Sharing Platform

Welcome to the absolute master documentation for **SafeShare ECC**, a Zero-Trust Secure File Sharing and Encrypted Cloud Storage system. This document is crafted to serve as an industry-grade software manual and an academic thesis support file. 

By reading this guide, you will gain an absolute, rock-solid grip on the system's design, mathematical foundations, code pipelines, and security mechanisms, enabling you to present it flawlessly during your final project viva defense.

---

## 📖 1. Executive Summary

Traditional cloud storage platforms (e.g., Google Drive, Dropbox) operate on an **implied trust model**, meaning the cloud servers hold the encryption keys. If the server is compromised, or a rogue administrator access is abused, the plaintext files are exposed.

**SafeShare ECC** implements a **Zero-Trust Cryptographic Architecture**.
* **Zero-Server Knowledge**: The hosting server never stores plaintext files, plaintext passwords, or raw user private keys.
* **Client-Decided Envelope Encryption**: Files are encrypted using a **hybrid cryptography pipeline** before transmission.
* **Cryptographic Signatures**: Every upload is cryptographically signed using Elliptic Curve Digital Signatures (ECDSA), ensuring sender authenticity and non-repudiation.
* **End-to-End Integrity**: Intercepting and altering database signatures or disk ciphertexts immediately triggers quarantine blocks at the download stage before decryption begins.

---

## 🔐 2. The Cryptographic Model (Mathematics & Primitives)

To provide maximum security with optimal performance, SafeShare ECC utilizes a **hybrid cryptosystem** combining asymmetric public-key cryptography (for key exchange and digital signing) and symmetric authenticated cryptography (for high-speed file encryption).

```
                 HYBRID CRYPTOGRAPHIC ENVELOPE
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  Sender Private Key (ECDSA) ────────► Digital Signature        │
│                                           │ (Binds Integrity)  │
│  Plaintext File ──► [AES-256-GCM] ──► Ciphertext Payload       │
│                           ▲                                    │
│                     Derived Symmetric Key (32-bytes)           │
│                           │                                    │
│                     [HKDF-SHA256]                              │
│                           │                                    │
│                 ECDH Shared Secret (Curve SECP256R1)           │
│                           ▲                                    │
│             ┌─────────────┴─────────────┐                      │
│             │                           │                      │
│     Ephemeral Private Key       Recipient Public Key           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 1. Elliptic Curve Cryptography (ECC)
* **Standard Curve**: **SECP256R1** (also known as NIST P-256 or prime256v1).
* **Why SECP256R1?**: It is an industry-standard curve approved by the NSA for Suite B cryptography. A 256-bit ECC key offers an equivalent security level to a **3072-bit RSA key** but results in vastly faster computations, smaller key sizes, and lower resource overhead.

### 2. Elliptic Curve Diffie-Hellman (ECDH)
* **Purpose**: Secure asymmetric key exchange.
* **Operation**: When Alice wants to send a file to Bob, she generates an in-memory **ephemeral ECC keypair** (temporary keypair discarded after use). She computes:
  $$\text{Shared Secret} = \text{ECDH}(\text{Ephemeral Private Key}, \text{Bob's Public Key})$$
  Bob will eventually compute the same shared secret on his side using:
  $$\text{Shared Secret} = \text{ECDH}(\text{Bob's Private Key}, \text{Ephemeral Public Key})$$
* **Security Benefit**: No attacker intercepting the database can derive this shared secret because the ephemeral private key is never saved anywhere.

### 3. HMAC-based Key Derivation Function (HKDF-SHA256)
* **Purpose**: Key stretching and extraction.
* **Operation**: The raw elliptic curve point coordinate derived from ECDH has non-uniform entropy. HKDF-SHA256 processes this shared point with a salt and context info string (`secure-file-transfer`) to derive a cryptographically strong, uniform, 32-byte key suitable for symmetric AES encryption.

### 4. AES-256-GCM (Galois/Counter Mode)
* **Purpose**: Authenticated Symmetric Encryption (AEAD).
* **Operation**: Encrypts the plaintext data with a 12-byte random Initialization Vector (nonce) and the 32-byte derived symmetric key.
* **GCM Authentication Tag**: AES-GCM generates a 16-byte integrity tag alongside the ciphertext. During decryption, GCM verifies this tag. If a single bit of ciphertext or nonce has changed, tag validation fails, preventing decryption side-channel leaks.

### 5. Elliptic Curve Digital Signature Algorithm (ECDSA)
* **Purpose**: Authenticity, integrity, and non-repudiation.
* **Operation**: The sender signs the encrypted ciphertext using their long-term private key and Curve SECP256R1 combined with a SHA-256 hash. The signature acts as an unforgeable digital seal showing that:
  1. The file was indeed sent by the declared owner.
  2. The encrypted payload has not been modified.

---

## 🔄 3. Detailed Step-by-Step Data Pipelines

### A. User Registration & Rest-Sealing (At-Rest Protection)
1. **Key Generation**: The client requests registration. The server generates a long-term **SECP256R1 ECC keypair** for the user.
2. **Double Encryption at Rest**:
   * The user's password is encrypted and salted using **bcrypt** with a work factor of 12 (standard protection against brute force).
   * The user's long-term **ECC Private Key** is serialized to PEM format, encrypted using **AES-256-GCM** with a master key (`CRYPTO_MASTER_KEY` loaded in the server environment), and stored in the database.
   * **Outcome**: Even if a hacker dumps the entire SQL database, they cannot read any user's private key because they are all sealed under the environment's master key.

### B. Secure File Upload Pipeline (Encrypt-then-Sign)
1. **Preparation**: Alice selects a file, specifies Bob as the recipient, and selects security flags (e.g., self-destruct).
2. **Key Synthesis**:
   * Alice's client requests Bob's public key from the database.
   * Generates a temporary **Ephemeral keypair**.
   * Performs **ECDH** using the Ephemeral Private Key and Bob's Public Key.
   * Derived shared secret is put through **HKDF-SHA256** to yield a 256-bit symmetric AES key.
3. **Encryption & Envelope Sealing**:
   * The plaintext file is encrypted using **AES-256-GCM** with the derived key and a 12-byte nonce.
   * The ciphertext is digitally signed by Alice using her long-term private key (**ECDSA-SHA256**).
4. **Storage**:
   * The raw encrypted ciphertext is written directly to the server's disk storage (`uploads/`).
   * The metadata is saved in the database: Ephemeral Public Key, Alice's signature, AES-GCM nonce, SHA-256 plaintext checksum, and expiry details.

### C. Secure Download & Quarantine Pipeline (Verify-then-Decrypt)
1. **Access Control**: Bob requests to download the file. The server validates Bob's JWT session to verify he is the authorized recipient.
2. **Signature Verification (First Wall)**:
   * The server reads the ciphertext from disk.
   * Fetches Alice's long-term public key and signature from the database.
   * Performs **ECDSA verification**. If verification fails, the server aborts, logs a `SIGNATURE_FORGERY` threat, and returns an HTTP 400.
3. **Decryption (Second Wall)**:
   * The server decrypts Bob's stored private key from the database using the master key.
   * Computes **ECDH** using Bob's Private Key and the Ephemeral Public Key of the file record.
   * Derives the symmetric AES key via **HKDF**.
   * Performs **AES-256-GCM decryption**. If the ciphertext was altered (even a single bit), GCM decryption throws an `InvalidTag` exception. The server immediately halts, logs a `TAMPERING_ATTEMPT` critical event, and returns an HTTP 400.
4. **Delivery**:
   * If both validation walls pass, the server streams the decrypted plaintext stream back to Bob's browser with headers showing signature validation success and the file's original SHA-256 checksum.

---

## 📁 4. System Architecture & Folder Layout

```
.
├── crypto_core/             # Native Cryptographic Libraries
│   ├── ecc.py               # Curve SECP256R1 keypair generation & serialization
│   ├── encryption.py        # Native AES-256-GCM AEAD encryption routines
│   ├── key_derivation.py    # ECDH secrets & HKDF-SHA256 key derivations
│   └── signature.py         # ECDSA digital signing and verification
├── backend/                 # FastAPI Backend REST Service
│   ├── database/            # PERSISTENCE: SQLite connection and SQLAlchemy Schemas
│   │   ├── models.py        # Users, Files, SharedFiles, Audit, Threat Logs
│   │   └── session.py       # Pool sessions & auto-migrations
│   ├── routes/              # ROUTERS: Business logic controllers
│   │   ├── auth.py          # Onboarding, bcrypt hashing, JWT emission
│   │   ├── files.py         # In-memory uploads, downloads, revocation
│   │   ├── users.py         # Recipient selection directory lookup
│   │   └── security.py      # Sealed audit feed, AI insights, Sandbox
│   ├── services/            # Cryptographic services layer
│   │   └── crypto_service.py # AES private key rest sealing & ECDH pipelines
│   └── main.py              # Application entrypoint & CORS configurations
├── frontend/                # React Vite SPA Web Interface
│   ├── src/                 
│   │   ├── components/      # UI components (TerminalLogs console shell)
│   │   ├── pages/           # Screen modules (Auth, Dashboard)
│   │   ├── App.jsx          # Root session manager and router
│   │   └── index.css        # Cyberpunk Tailwind v4 design system
│   └── nginx.conf           # Production Nginx web server settings
└── tests/                   # Security test suite (pytest)
```

---

## 🗄️ 5. Database Schema & Persistence Model

The application utilizes five relational database tables to manage zero-trust assets:

```
                  ┌───────────────┐
                  │     users     │
                  └───────┬───────┘
                          │ 1
                          │
          ┌───────────────┼───────────────┐
          │ 1..*          │ 1..*          │ 1..*
  ┌───────▼───────┐┌──────▼───────┐┌──────▼────────┐
  │     files     ││  audit_logs  ││security_events│
  └───────┬───────┘└──────────────┘└───────────────┘
          │ 1
          │
          │ 1..*
  ┌───────▼───────┐
  │ shared_files  │
  └───────────────┘
```

### 1. `users` Table
* `id` (Integer, Primary Key): Unique database identifier.
* `username` (String, Unique): Identification tag for credentials check.
* `email` (String, Unique): Recovery and search directory field.
* `password_hash` (String): Secure salted **bcrypt** password representation.
* `public_key` (Text): The user's long-term **SECP256R1 Public Key** in PEM format.
* `private_key_encrypted` (Text): The user's **SECP256R1 Private Key**, sealed at rest via **AES-256-GCM** using the system master key.

### 2. `files` Table
* `id` (String, Primary Key): Secure generated **UUIDv4** string representing the file.
* `filename` (String): Original plaintext name of the file.
* `file_size` (Integer): Plaintext size in bytes.
* `owner_id` (Integer, Foreign Key): Reference to the sender's user ID.
* `recipient_id` (Integer, Foreign Key): Reference to the authorized recipient's user ID.
* `nonce` (String): The **AES-256-GCM 12-byte initialization vector** (hex-encoded).
* `signature` (String): The **ECDSA-SHA256 signature** representing the ciphertext (hex-encoded).
* `ephemeral_public` (Text): The temporary **ephemeral public key** (PEM) used to derive the shared secret.
* `sha256_checksum` (String): The raw **SHA-256 hash** of the plaintext file bytes.
* `expiry_at` (DateTime, Nullable): Time when file becomes automatically unavailable.
* `one_time_download` (Boolean): Flag representing self-destruct upon single access.
* `is_downloaded` (Boolean): Download tracking flag.
* `original_signature` (String): Backup signature utilized to repair forged states in the sandbox.

### 3. `shared_files` Table
Handles downstream multi-user file sharing. When Alice shares an existing file with Charlie, the system decrypts the original file in memory and re-encrypts it specifically for Charlie's public key, storing a separate record:
* `id` (Integer, Primary Key): Unique share ID.
* `file_id` (String, Foreign Key): References the parent file record.
* `shared_by_id` (Integer, Foreign Key): Sender user ID.
* `shared_with_id` (Integer, Foreign Key): Target recipient user ID.
* `nonce` (String): Specific AES-GCM nonce for this shared ciphertext capsule.
* `signature` (String): Specific ECDSA signature for this shared ciphertext capsule.
* `ephemeral_public` (Text): Ephemeral public key created specifically for this share exchange.

### 4. `audit_logs` Table (Zero-Trust Compliant)
In compliance with zero-trust logging practices, all system user transactions are fully encrypted before writing to database logs.
* `id` (Integer, Primary Key): Log identifier.
* `user_id` (Integer, Foreign Key): User reference.
* `action_encrypted` (Text): Transaction category (e.g., `UPLOAD`, `DOWNLOAD`) encrypted via AES-256-GCM.
* `details_encrypted` (Text): Explanatory log text encrypted via AES-256-GCM.
* `ip_address_encrypted` (Text): User host IP address encrypted via AES-256-GCM.

### 5. `security_events` Table (Threat Log)
Maintains unencrypted system intrusion events for the Threat Intelligence Feed.
* `id` (Integer, Primary Key): Threat ID.
* `event_type` (String): Threat category (`TAMPERING_ATTEMPT`, `SIGNATURE_FORGERY`, `INVALID_LOGIN`, `UNAUTHORIZED_ACCESS`).
* `severity` (String): Event impact assessment level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `details` (Text): Detailed log outlining the attack vector parameters.
* `ip_address` (String): Source IP of the attacker.

---

## 🎨 6. Dynamic UI Features

The React frontend features a premium, interactive cyber-defense control interface styled using **Tailwind CSS v4** with a custom dark theme:

1. **Collapsible Terminal Shell Console**: A persistent, real-time command console at the bottom of the screen. Using a global event trigger, it outputs low-level cryptographic operations as they run (e.g., "Performing ECDH point multiplication...", "GCM tag validated!").
2. **Animated Key Generator Auth Interface**: During registration, users can watch an interactive, animated terminal simulation showing their SECP256R1 keys generating, HKDF key derivation, and private key vault sealing.
3. **Crypto Vault & Inbox Tabs**: Separates files owned by the user and files sent to them by others. Displays integrity verification ticks, checksums, and secure options.
4. **Secure QR-Code Generator**: Instantly displays a cryptographic download token wrapped in a mobile-scannable QR code.
5. **AI Threat Intelligence Insights**: Dynamically evaluates database events to calculate a system **Health Score (0-100%)** and output threat notifications.
6. **Attack Simulator Sandbox**: Provides a complete interactive laboratory allowing users to trigger MitM disk corruption and database signature forgery to verify zero-trust quarantine defenses.

---

## 🧪 7. The Attack Simulator & Secure Defense Laboratory

One of the most impressive parts of the project to show examiners is the **Attack Simulator Sandbox**. It mathematically demonstrates why the platform is resilient against advanced threat models.

```
                         THE SECURE DOUBLE-WALL DEFENSE
                         
                         Active Interception / Attack
                                      │
                                      ▼
                        ┌──────────────────────────┐
                        │   1. ECDSA Signature?    │───[Invalid Signature]───► BLOCKED!
                        └─────────────┬────────────┘                           Logs Forgery Event
                                      │
                                      ▼ [Valid Signature]
                        ┌──────────────────────────┐
                        │    2. AES-GCM AEAD Tag?  │───[Tag Mismatch]────────► BLOCKED!
                        └─────────────┬────────────┘                           Logs Tampering Event
                                      │
                                      ▼ [Valid GCM Tag]
                        ┌──────────────────────────┐
                        │    Decrypted Plaintext   │───► Served Securely!
                        └──────────────────────────┘
```

### Attack Scenario A: Man-in-the-Middle (MitM) Ciphertext Tampering
* **Threat Model**: An attacker gains root access to the hosting server's hard disk and modifies a file's encrypted contents directly in storage (or intercept and modify bytes in transit).
* **Simulation**: Clicking **Corrupt Ciphertext** flips bits in the middle of the stored `.enc` file.
* **Defense Response**: When a user attempts to download this file, the server runs ECDSA verification. Since the signature was calculated over the *original* ciphertext, the modified bytes result in a signature mismatch. If the signature check is bypassed, the decryption pipeline will trigger an **AES-GCM `InvalidTag` exception**.
* **Visual Output**: The download is immediately blocked, a `TAMPERING_ATTEMPT` or `SIGNATURE_FORGERY` alarm displays, and the AI Health Score drops significantly.

### Attack Scenario B: Database Breach & Signature Forgery
* **Threat Model**: An attacker gains full access to the SQLite/MySQL database and modifies a file's signature field to bypass validation or upload a rogue file in place of the original.
* **Simulation**: Clicking **Forge Signature** overwrites the database signature column with random hex data.
* **Defense Response**: The server attempts to verify the signature of the ciphertext against the database value. Since the signature is unforgeable without the sender's private key, verification fails.
* **Visual Output**: The download is blocked immediately, raising a `SIGNATURE_FORGERY` event *before* symmetric decryption even initiates, preventing decryption side-channel attacks.

### System Recovery (Repair Mode)
* **Simulation**: Clicking **Repair File** restores the original signature from the backup database column and replaces the corrupted ciphertext with a secure local backup.
* **Defense Response**: The file's integrity score returns to nominal, the AI score climbs back to 100%, and downloads succeed normally.

---

## 🎓 8. Final Project Viva Q&A Cheat Sheet (Guaranteed Success!)

Prepare for your project defense using this comprehensive compilation of questions examiners are likely to ask, complete with concise, professional answers:

### Q1: What is the core security model of this application?
**Answer**: "The core model is **Zero-Trust Hybrid Cryptography**. The server acts as a zero-knowledge storage vault. Symmetric file encryption is handled via **AES-256-GCM**, where keys are derived on-the-fly using **ECDH Key Exchange** (Curve SECP256R1) combined with **HKDF-SHA256**. Files are digitally signed using **ECDSA** to guarantee integrity and authenticity. User private keys are sealed at rest in the database using a master-key envelope, ensuring that even in a complete database compromise, no plaintext private keys or files are exposed."

### Q2: Why did you choose hybrid cryptography instead of just asymmetric ECC?
**Answer**: "Asymmetric cryptography (like ECC or RSA) is computationally expensive and is mathematically unsuitable for encrypting large files. Symmetric ciphers (like AES) are exceptionally fast but require a pre-shared key. By combining them, we get the best of both worlds: we use **ECDH** to securely exchange a derived key, and then use **AES-256-GCM** to encrypt the actual file payload with maximum performance."

### Q3: What is AES-GCM, and how is it different from standard AES-CBC?
**Answer**: "AES-CBC is a simple block-cipher mode that provides confidentiality but does not guarantee integrity; it requires a separate MAC (like HMAC) to detect modifications and is vulnerable to padding oracle attacks. **AES-GCM** is an **AEAD (Authenticated Encryption with Associated Data)** mode. It provides confidentiality and authenticity in a single operation by producing an integrity tag. If an attacker alters even a single bit of GCM ciphertext, tag validation fails, preventing padding or decryption side-channel attacks."

### Q4: If an attacker hacks the database, can they decrypt the stored files?
**Answer**: "No. Decrypting the files requires the recipient's long-term **ECC Private Key** and the file's **ephemeral public key**. The ephemeral public key is stored in the database, but the recipient's private key is stored **fully encrypted (sealed)** using AES-256-GCM with a high-entropy master key (`CRYPTO_MASTER_KEY`) loaded in the server's environment. Without access to both the database and the server's environment variables, the stored files are mathematically impossible to decrypt."

### Q5: Explain your "Encrypt-then-Sign" paradigm. Why is the signature calculated over the ciphertext instead of the plaintext?
**Answer**: "SafeShare ECC implements the industry-recommended **Encrypt-then-Sign** paradigm. We encrypt the plaintext first to yield the ciphertext, and then generate an ECDSA signature over the ciphertext payload. This provides two key security advantages:
1. **Performance & Security**: The receiver can verify the authenticity of the signature *before* running any decryption operations. If the signature is forged, the request is rejected immediately, preventing costly decryption side-channel or DoS attacks.
2. **Plaintext Protection**: Signing the plaintext directly could leak patterns or information about the original file."

### Q6: How does the system handle multi-user secure sharing if the server holds no private keys?
**Answer**: "When Alice wants to share an already uploaded file with Charlie, she uses the **Multi-User Sharing Center**. The server securely loads the file's original encrypted bytes. Under zero-trust session authorization, the server temporarily decrypts the payload in memory, generates a new ephemeral keypair, performs a new **ECDH Key Exchange** with Charlie's public key, derives a new AES key, encrypts the file, signs it, and writes a recipient-specific ciphertext capsule for Charlie. This ensures Charlie gets access without ever exposing Alice's private key or persisting plaintext on disk."

### Q7: What are the audit logs encrypted?
**Answer**: "Standard audit logs often leak metadata (e.g., who accessed what files, when, and from what IP). To maintain zero-trust integrity, the backend encrypts all audit trail fields (actions, details, IP addresses) using AES-256-GCM under the master key before writing to the SQLite database. The logs are decrypted in-memory only when the authorized owner requests them."

### Q8: How does the "One-Time Download" self-destruct mechanism work?
**Answer**: "When a file is flagged as a one-time download, the server allows its verified decryption and streams it back to the client. The moment the stream completes, the server triggers a deletion transaction: it purges the file record, deletes the encrypted file from the hard drive, and cascadingly removes all associated sharing links, preventing any subsequent access."
