import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure the root workspace directory is in the import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database.session import engine, Base
from backend.routes import auth, users, files, security

# Print a professional boot banner to the terminal
print("\n" + "="*80)
print("  🚀 SECURE FILE TRANSFER & SHARING SYSTEM  [ECC + AES-GCM HYBRID CRYPTO]  ")
print("  Zero-Trust Cloud Storage & Multi-User Sharing Framework (SECP256R1)")
print("="*80)
print("[BOOT] Initializing secure database connection...")

# Automatically initialize SQLite tables on startup
Base.metadata.create_all(bind=engine)
print("[BOOT] Database tables loaded successfully.")

app = FastAPI(
    title="Zero-Trust Secure File Sharing Platform API",
    description="Industry-grade secure file transfer backend using SECP256R1 ECDH Key Exchange, AES-256-GCM symmetric encryption, and ECDSA digital signatures.",
    version="1.0.0"
)

# CORS Configuration for React Frontend connection
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under unified '/api' path prefix
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(files.router, prefix="/api")
app.include_router(security.router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "status": "ONLINE",
        "cryptography": "ECDHSEC SECP256R1 + AES-256-GCM + ECDSA SHA-256",
        "zero_trust": "ENABLED",
        "documentation": "/docs"
    }

print("[BOOT] Unified API routers loaded: /auth, /users, /files, /security")
print("[BOOT] CORS policies configured.")
print("[BOOT] System fully armed. Ready for secure file transfers.")
print("="*80 + "\n")
