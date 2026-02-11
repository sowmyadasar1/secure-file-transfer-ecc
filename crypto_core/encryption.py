import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_data(data: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_data(nonce: bytes, ciphertext: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)