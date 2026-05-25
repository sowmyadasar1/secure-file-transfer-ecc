import sys
import os
import hashlib

# Ensure parent directory is in sys.path to easily import crypto_core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from crypto_core.ecc import (
    generate_ecc_keys,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key
)
from crypto_core.key_derivation import derive_shared_secret, derive_aes_key
from crypto_core.encryption import encrypt_data, decrypt_data
from crypto_core.signature import sign_data, verify_signature
from backend.config import CRYPTO_MASTER_KEY


# --- MASTER KEY HELPERS (For Private Keys and Audit Logs) ---

def encrypt_with_master_key(data_str: str) -> str:
    """Encrypts a plaintext string using AES-256-GCM with the CRYPTO_MASTER_KEY."""
    if not data_str:
        return ""
    nonce, ciphertext = encrypt_data(data_str.encode("utf-8"), CRYPTO_MASTER_KEY)
    return f"{nonce.hex()}:{ciphertext.hex()}"


def decrypt_with_master_key(encrypted_str: str) -> str:
    """Decrypts a ciphertext hex-string using AES-256-GCM with the CRYPTO_MASTER_KEY."""
    if not encrypted_str:
        return ""
    try:
        parts = encrypted_str.split(":")
        if len(parts) != 2:
            raise ValueError("Invalid encrypted string format")
        nonce_hex, ciphertext_hex = parts
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = decrypt_data(nonce, ciphertext, CRYPTO_MASTER_KEY)
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


# --- USER KEY GENERATION ---

def generate_user_keypair():
    """
    Generates a secure ECC SECP256R1 keypair.
    Returns:
        public_key_pem (str): Plaintext public key PEM
        private_key_encrypted (str): Encrypted private key PEM (stored at rest)
    """
    private_key, public_key = generate_ecc_keys()
    
    # Serialize to PEM
    pub_pem = serialize_public_key(public_key).decode("utf-8")
    priv_pem = serialize_private_key(private_key).decode("utf-8")
    
    # Encrypt private key with Master Key
    priv_encrypted = encrypt_with_master_key(priv_pem)
    
    return pub_pem, priv_encrypted


# --- FILE CRYPTOGRAPHY WORKFLOWS ---

def encrypt_file_for_recipient(file_bytes: bytes, recipient_pub_pem: str, sender_priv_encrypted: str):
    """
    Implements Phase 2 Secure File Upload Flow:
    1. Ephemeral key pair generation.
    2. ECDH using Ephemeral Private Key + Recipient's Long-term Public Key.
    3. AES-256 key derivation via HKDF.
    4. Encrypt file using AES-256-GCM.
    5. Digitally sign ciphertext using Sender's decrypted Private Key.
    
    Returns:
        ciphertext (bytes): Encrypted file bytes
        nonce (str): Hex encoded nonce
        signature (str): Hex encoded signature of ciphertext
        ephemeral_pub_pem (str): Ephemeral Public Key in PEM format (to store in DB)
        sha256_checksum (str): SHA-256 checksum of plaintext file bytes
    """
    # 1. Ephemeral Keypair
    ephemeral_priv, ephemeral_pub = generate_ecc_keys()
    ephemeral_pub_pem = serialize_public_key(ephemeral_pub).decode("utf-8")
    
    # 2. ECDH Shared Secret
    recipient_pub = load_public_key(recipient_pub_pem.encode("utf-8"))
    shared_secret = derive_shared_secret(ephemeral_priv, recipient_pub)
    
    # 3. HKDF AES Key Derivation
    aes_key = derive_aes_key(shared_secret)
    
    # 4. AES-256-GCM Encryption
    nonce_bytes, ciphertext = encrypt_data(file_bytes, aes_key)
    
    # 5. Sign Ciphertext using Sender's Private Key
    sender_priv_pem = decrypt_with_master_key(sender_priv_encrypted)
    sender_priv = load_private_key(sender_priv_pem.encode("utf-8"))
    signature_bytes = sign_data(sender_priv, ciphertext)
    
    # 6. Compute checksum of plaintext
    checksum = hashlib.sha256(file_bytes).hexdigest()
    
    return ciphertext, nonce_bytes.hex(), signature_bytes.hex(), ephemeral_pub_pem, checksum


def decrypt_file_for_recipient(
    ciphertext: bytes,
    nonce_hex: str,
    signature_hex: str,
    ephemeral_pub_pem: str,
    sender_pub_pem: str,
    recipient_priv_encrypted: str
) -> bytes:
    """
    Implements Phase 3 Secure File Download Flow:
    1. Verify ECDSA signature of ciphertext using Sender's Long-term Public Key.
    2. Load Recipient's decrypted Private Key.
    3. Perform ECDH using Recipient's Private Key + Ephemeral Public Key from DB.
    4. Derive AES-256 key via HKDF.
    5. Decrypt using AES-256-GCM.
    
    Raises:
        cryptography.exceptions.InvalidSignature: If signature verification fails
        cryptography.hazmat.primitives.ciphers.aead.InvalidTag: If GCM decryption fails (tampering)
    """
    # 1. Verify ECDSA Signature first
    sender_pub = load_public_key(sender_pub_pem.encode("utf-8"))
    signature_bytes = bytes.fromhex(signature_hex)
    
    # This will raise InvalidSignature if verification fails (detected as Signature Forgery)
    verify_signature(sender_pub, signature_bytes, ciphertext)
    
    # 2. Recipient Private Key decryption
    recipient_priv_pem = decrypt_with_master_key(recipient_priv_encrypted)
    recipient_priv = load_private_key(recipient_priv_pem.encode("utf-8"))
    
    # 3. ECDH Shared Secret
    ephemeral_pub = load_public_key(ephemeral_pub_pem.encode("utf-8"))
    shared_secret = derive_shared_secret(recipient_priv, ephemeral_pub)
    
    # 4. HKDF AES Key Derivation
    aes_key = derive_aes_key(shared_secret)
    
    # 5. Decrypt using AES-256-GCM
    nonce_bytes = bytes.fromhex(nonce_hex)
    
    # This will raise InvalidTag if decryption fails (detected as Ciphertext Tampering)
    plaintext = decrypt_data(nonce_bytes, ciphertext, aes_key)
    
    return plaintext
