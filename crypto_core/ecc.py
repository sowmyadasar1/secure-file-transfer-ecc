from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_ecc_keys():
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_data):
    return serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )


def load_public_key(pem_data):
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )