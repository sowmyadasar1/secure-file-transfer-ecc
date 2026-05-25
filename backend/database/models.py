import datetime
import uuid
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from backend.database.session import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    public_key = Column(Text, nullable=False)  # PEM format
    private_key_encrypted = Column(Text, nullable=False)  # PEM encrypted with AES-256-GCM
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    owned_files = relationship("File", foreign_keys="File.owner_id", back_populates="owner")
    received_files = relationship("File", foreign_keys="File.recipient_id", back_populates="recipient")
    shares_sent = relationship("SharedFile", foreign_keys="SharedFile.shared_by_id", back_populates="shared_by")
    shares_received = relationship("SharedFile", foreign_keys="SharedFile.shared_with_id", back_populates="shared_with")
    audit_logs = relationship("AuditLog", back_populates="user")
    security_events = relationship("SecurityEvent", back_populates="user")


class File(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Cryptography
    nonce = Column(String, nullable=False)  # Hex/Base64 encoded IV
    signature = Column(String, nullable=False)  # Hex/Base64 signature of ciphertext
    ephemeral_public = Column(Text, nullable=False)  # PEM format of ephemeral ECC key
    sha256_checksum = Column(String, nullable=False)  # Hex checksum of plaintext
    
    # Security options
    expiry_at = Column(DateTime, nullable=True)
    one_time_download = Column(Boolean, default=False)
    is_downloaded = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Backup properties for the Attack Sandbox Simulator
    original_signature = Column(String, nullable=True)  # Backup for restoring

    # Relationships
    owner = relationship("User", foreign_keys=[owner_id], back_populates="owned_files")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_files")
    shares = relationship("SharedFile", back_populates="file", cascade="all, delete-orphan")


class SharedFile(Base):
    __tablename__ = "shared_files"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    file_id = Column(String, ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    shared_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    shared_with_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Recipient-specific key capsule and signature
    nonce = Column(String, nullable=False)
    signature = Column(String, nullable=False)
    ephemeral_public = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Backup properties for simulator
    original_signature = Column(String, nullable=True)

    # Relationships
    file = relationship("File", back_populates="shares")
    shared_by = relationship("User", foreign_keys=[shared_by_id], back_populates="shares_sent")
    shared_with = relationship("User", foreign_keys=[shared_with_id], back_populates="shares_received")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Encrypted fields (AES-256-GCM using CRYPTO_MASTER_KEY)
    action_encrypted = Column(Text, nullable=False)
    details_encrypted = Column(Text, nullable=False)
    ip_address_encrypted = Column(Text, nullable=False)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audit_logs")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_type = Column(String, nullable=False)  # e.g., TAMPERING_ATTEMPT, SIGNATURE_FORGERY
    severity = Column(String, nullable=False)    # e.g., LOW, MEDIUM, HIGH, CRITICAL
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    details = Column(Text, nullable=False)
    ip_address = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="security_events")
