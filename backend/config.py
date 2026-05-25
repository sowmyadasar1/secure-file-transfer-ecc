import os
import secrets
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Environment variables with safe fallbacks
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# Master key for AES-GCM (must be exactly 32 bytes for AES-256)
# If provided in env, we expect it to be a 32-byte hex or base64 string.
# By default, we generate a persistent key inside the workspace .env if not present,
# or a secure in-memory fallback. Let's make sure it's 32 bytes.
default_master_key_hex = secrets.token_hex(32)
env_master_key = os.getenv("CRYPTO_MASTER_KEY")

if env_master_key:
    # If the provided key is in hex and has 64 hex chars (32 bytes), convert to bytes
    try:
        if len(env_master_key) == 64:
            CRYPTO_MASTER_KEY = bytes.fromhex(env_master_key)
        else:
            # Otherwise use sha256 to hash it to a 32-byte key securely
            import hashlib
            CRYPTO_MASTER_KEY = hashlib.sha256(env_master_key.encode()).digest()
    except Exception:
        import hashlib
        CRYPTO_MASTER_KEY = hashlib.sha256(env_master_key.encode()).digest()
else:
    # For dev speed and persistence, let's check a local .env file or create one
    dotenv_path = BASE_DIR / ".env"
    if dotenv_path.exists():
        with open(dotenv_path, "r") as f:
            for line in f:
                if line.startswith("CRYPTO_MASTER_KEY="):
                    val = line.strip().split("=")[1]
                    try:
                        CRYPTO_MASTER_KEY = bytes.fromhex(val)
                    except Exception:
                        CRYPTO_MASTER_KEY = bytes.fromhex(default_master_key_hex)
                    break
            else:
                CRYPTO_MASTER_KEY = bytes.fromhex(default_master_key_hex)
    else:
        # Create a default .env
        with open(dotenv_path, "w") as f:
            f.write(f"CRYPTO_MASTER_KEY={default_master_key_hex}\n")
            f.write(f"SECRET_KEY={SECRET_KEY}\n")
        CRYPTO_MASTER_KEY = bytes.fromhex(default_master_key_hex)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/secure_file_transfer.db")
