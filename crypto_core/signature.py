from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )


def verify_signature(public_key, signature: bytes, data: bytes):
    public_key.verify(
        signature,
        data,
        ec.ECDSA(hashes.SHA256())
    )