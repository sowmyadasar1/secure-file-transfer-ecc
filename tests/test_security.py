import os
import shutil
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Setup environment overrides for test DB before importing main app
os.environ["DATABASE_URL"] = "sqlite:///./secure_file_transfer_test.db"

from backend.main import app
from backend.database.session import Base, get_db
from backend.database.models import User, File, SecurityEvent
from backend.routes.files import get_file_path

# Create test database
engine = create_engine("sqlite:///./secure_file_transfer_test.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db dependency in FastAPI
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    # Setup test tables
    Base.metadata.create_all(bind=engine)
    yield
    # Clean up test database and test uploads folder
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./secure_file_transfer_test.db"):
        os.remove("./secure_file_transfer_test.db")
    
    # Clean up any test files in the uploads folder
    # Upload folder for testing will still map to backend/uploads or parent uploads/
    # If the tests created any backups or files, we can let them persist or clean them
    pass


def test_auth_registration_and_login():
    # 1. Register User A (Alice)
    reg_response = client.post("/api/auth/register", json={
        "username": "alice",
        "email": "alice@security.io",
        "password": "supersecretpassword123"
    })
    assert reg_response.status_code == 201
    data = reg_response.json()
    assert data["username"] == "alice"
    assert "public_key" in data
    
    # 2. Register User B (Bob)
    reg_bob = client.post("/api/auth/register", json={
        "username": "bob",
        "email": "bob@security.io",
        "password": "supersecretbobpassword"
    })
    assert reg_bob.status_code == 201

    # 3. Login Alice
    login_response = client.post("/api/auth/login", json={
        "username": "alice",
        "password": "supersecretpassword123"
    })
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert "access_token" in login_data
    assert login_data["user"]["username"] == "alice"


def test_secure_file_upload_and_download():
    # 1. Login Alice & Bob to get JWTs and user info
    login_alice = client.post("/api/auth/login", json={"username": "alice", "password": "supersecretpassword123"}).json()
    alice_token = login_alice["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    
    login_bob = client.post("/api/auth/login", json={"username": "bob", "password": "supersecretbobpassword"}).json()
    bob_headers = {"Authorization": f"Bearer {login_bob['access_token']}"}
    bob_id = login_bob["user"]["id"]

    # 2. Alice uploads an encrypted file for Bob
    file_content = b"Top Secret Payload: Zero-Trust Protocols Active."
    files = {"file": ("intel.txt", file_content, "text/plain")}
    data = {"recipient_id": bob_id, "one_time_download": False}
    
    upload_res = client.post(
        "/api/files/upload", 
        headers=alice_headers, 
        files=files, 
        data=data
    )
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    file_id = upload_data["id"]

    # 3. Bob downloads and decrypts the file successfully
    download_res = client.get(
        f"/api/files/download/{file_id}", 
        headers=bob_headers
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content
    assert download_res.headers["X-Signature-Verification"] == "SUCCESS"


def test_tampering_attack_detection():
    # 1. Login Alice & Bob
    login_alice = client.post("/api/auth/login", json={"username": "alice", "password": "supersecretpassword123"}).json()
    alice_headers = {"Authorization": f"Bearer {login_alice['access_token']}"}
    
    login_bob = client.post("/api/auth/login", json={"username": "bob", "password": "supersecretbobpassword"}).json()
    bob_headers = {"Authorization": f"Bearer {login_bob['access_token']}"}
    bob_id = login_bob["user"]["id"]

    # 2. Upload file
    files = {"file": ("classified.txt", b"Sensitive Data", "text/plain")}
    upload_res = client.post("/api/files/upload", headers=alice_headers, files=files, data={"recipient_id": bob_id})
    file_id = upload_res.json()["id"]

    # 3. Corrupt file on disk via simulator endpoint
    corrupt_res = client.post(
        f"/api/security/simulate/corrupt/{file_id}", 
        headers=alice_headers
    )
    assert corrupt_res.status_code == 200

    # 4. Attempt Bob download -> MUST FAIL due to Ciphertext Alteration / Signature verification failure!
    download_res = client.get(
        f"/api/files/download/{file_id}", 
        headers=bob_headers
    )
    assert download_res.status_code == 400
    assert any(x in download_res.json()["detail"] for x in ["AES-GCM", "Signature", "verification failed", "forged"])

    # 5. Verify security event was logged in DB
    db = TestingSessionLocal()
    event = db.query(SecurityEvent).filter(
        (SecurityEvent.user_id == bob_id)
    ).first()
    assert event is not None
    assert any(x in event.details.lower() for x in ["failed", "forger", "aes-gcm", "signature"])
    db.close()

    # 6. Repair file
    repair_res = client.post(f"/api/security/simulate/repair/{file_id}", headers=alice_headers)
    assert repair_res.status_code == 200

    # 7. Bob download -> MUST NOW SUCCEED
    download_success = client.get(f"/api/files/download/{file_id}", headers=bob_headers)
    assert download_success.status_code == 200
    assert download_success.content == b"Sensitive Data"


def test_signature_forgery_detection():
    # 1. Login
    login_alice = client.post("/api/auth/login", json={"username": "alice", "password": "supersecretpassword123"}).json()
    alice_headers = {"Authorization": f"Bearer {login_alice['access_token']}"}
    login_bob = client.post("/api/auth/login", json={"username": "bob", "password": "supersecretbobpassword"}).json()
    bob_headers = {"Authorization": f"Bearer {login_bob['access_token']}"}
    bob_id = login_bob["user"]["id"]

    # 2. Upload
    files = {"file": ("signed_payload.bin", b"Asymmetric Signature Verification Test", "application/octet-stream")}
    upload_res = client.post("/api/files/upload", headers=alice_headers, files=files, data={"recipient_id": bob_id})
    file_id = upload_res.json()["id"]

    # 3. Forge signature in DB
    forge_res = client.post(f"/api/security/simulate/forge/{file_id}", headers=alice_headers)
    assert forge_res.status_code == 200

    # 4. Bob downloads -> MUST FAIL immediately due to ECDSA Signature verification failure
    download_res = client.get(f"/api/files/download/{file_id}", headers=bob_headers)
    assert download_res.status_code == 400
    assert "verification failed" in download_res.json()["detail"].lower()

    # 5. Verify security event was logged
    db = TestingSessionLocal()
    event = db.query(SecurityEvent).filter(SecurityEvent.event_type == "SIGNATURE_FORGERY").first()
    assert event is not None
    db.close()


def test_unauthorized_access_control():
    # 1. Register User C (Eve)
    client.post("/api/auth/register", json={
        "username": "eve",
        "email": "eve@attacker.com",
        "password": "evepassword123"
    })
    login_eve = client.post("/api/auth/login", json={"username": "eve", "password": "evepassword123"}).json()
    eve_headers = {"Authorization": f"Bearer {login_eve['access_token']}"}

    # 2. Alice logins and uploads file for Alice (Personal Vault)
    login_alice = client.post("/api/auth/login", json={"username": "alice", "password": "supersecretpassword123"}).json()
    alice_headers = {"Authorization": f"Bearer {login_alice['access_token']}"}
    alice_id = login_alice["user"]["id"]

    files = {"file": ("diary.txt", b"Alice Personal Diary", "text/plain")}
    upload_res = client.post("/api/files/upload", headers=alice_headers, files=files, data={"recipient_id": alice_id})
    file_id = upload_res.json()["id"]

    # 3. Eve attempts to download Alice's personal file -> MUST GET 403 FORBIDDEN
    eve_download = client.get(f"/api/files/download/{file_id}", headers=eve_headers)
    assert eve_download.status_code == 403
    assert "unauthorized access" in eve_download.json()["detail"].lower()
