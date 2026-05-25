import datetime
import os
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, Form, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session
from io import BytesIO
from backend.config import UPLOAD_DIR
from backend.database.session import get_db
from backend.database.models import User, File, SharedFile, AuditLog, SecurityEvent
from backend.routes.auth import get_current_user, log_audit, log_security_event
from backend.services.crypto_service import (
    encrypt_file_for_recipient,
    decrypt_file_for_recipient,
    load_public_key,
    load_private_key,
    decrypt_with_master_key
)
from cryptography.exceptions import InvalidSignature, InvalidTag

router = APIRouter(prefix="/files", tags=["Files"])


# --- HELPERS ---

def get_file_path(file_id: str, is_shared: bool = False) -> str:
    prefix = "shared_" if is_shared else ""
    return os.path.join(UPLOAD_DIR, f"{prefix}{file_id}.enc")


# --- ROUTE HANDLERS ---

@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    request: Request,
    file: UploadFile,
    recipient_id: int = Form(None),
    expiry_hours: int = Form(None),
    one_time_download: bool = Form(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = request.client.host if request.client else "127.0.0.1"
    
    # 1. Determine recipient
    if recipient_id is None:
        recipient = current_user
    else:
        recipient = db.query(User).filter(User.id == recipient_id).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient user not found")

    # 2. Read plaintext file bytes (no temp files written to disk!)
    file_bytes = await file.read()
    file_size = len(file_bytes)
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Cannot upload an empty file")

    # 3. Perform Hybrid Encryption & Signing
    try:
        ciphertext, nonce, signature, ephemeral_pub, checksum = encrypt_file_for_recipient(
            file_bytes=file_bytes,
            recipient_pub_pem=recipient.public_key,
            sender_priv_encrypted=current_user.private_key_encrypted
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cryptographic operation failed: {str(e)}")

    # 4. Generate metadata & store ciphertext on disk
    new_file = File(
        filename=file.filename,
        file_size=file_size,
        owner_id=current_user.id,
        recipient_id=recipient.id,
        nonce=nonce,
        signature=signature,
        ephemeral_public=ephemeral_pub,
        sha256_checksum=checksum,
        one_time_download=one_time_download,
        is_downloaded=False
    )
    
    # Save original signature in backup for simulator resetting
    new_file.original_signature = signature

    if expiry_hours and expiry_hours > 0:
        new_file.expiry_at = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)

    db.add(new_file)
    db.commit()
    db.refresh(new_file)

    # Write ciphertext to disk
    ciphertext_path = get_file_path(new_file.id)
    with open(ciphertext_path, "wb") as f:
        f.write(ciphertext)

    # Log successful upload
    log_audit(
        db, 
        current_user.id, 
        "UPLOAD", 
        f"Uploaded '{file.filename}' encrypted for {recipient.username}. File ID: {new_file.id}", 
        ip
    )

    return {
        "id": new_file.id,
        "filename": new_file.filename,
        "file_size": new_file.file_size,
        "recipient": recipient.username,
        "sha256_checksum": new_file.sha256_checksum,
        "expiry_at": new_file.expiry_at,
        "one_time_download": new_file.one_time_download
    }


@router.get("")
def list_my_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns files categorized into:
    1. owned: Files uploaded by current user
    2. received: Files uploaded by others specifically for current user
    3. shared_by_me: Files owned by me that I shared with others
    4. shared_with_me: Files owned by others that they shared with me
    """
    # 1. Owned files
    owned = db.query(File).filter(File.owner_id == current_user.id).all()
    
    # 2. Received files (direct uploads from others)
    received = db.query(File).filter((File.recipient_id == current_user.id) & (File.owner_id != current_user.id)).all()
    
    # 3. Shares sent by me
    shares_sent = db.query(SharedFile).filter(SharedFile.shared_by_id == current_user.id).all()
    
    # 4. Shares received by me
    shares_received = db.query(SharedFile).filter(SharedFile.shared_with_id == current_user.id).all()

    return {
        "owned": [
            {
                "id": f.id,
                "filename": f.filename,
                "file_size": f.file_size,
                "recipient_username": f.recipient.username,
                "recipient_id": f.recipient_id,
                "sha256_checksum": f.sha256_checksum,
                "expiry_at": f.expiry_at,
                "one_time_download": f.one_time_download,
                "is_downloaded": f.is_downloaded,
                "created_at": f.created_at,
                "is_expired": f.expiry_at < datetime.datetime.utcnow() if f.expiry_at else False,
                "tampered": not os.path.exists(get_file_path(f.id)) and not f.is_downloaded
            }
            for f in owned
        ],
        "received": [
            {
                "id": f.id,
                "filename": f.filename,
                "file_size": f.file_size,
                "owner_username": f.owner.username,
                "owner_id": f.owner_id,
                "sha256_checksum": f.sha256_checksum,
                "expiry_at": f.expiry_at,
                "one_time_download": f.one_time_download,
                "is_downloaded": f.is_downloaded,
                "created_at": f.created_at,
                "is_expired": f.expiry_at < datetime.datetime.utcnow() if f.expiry_at else False,
                "tampered": not os.path.exists(get_file_path(f.id)) and not f.is_downloaded
            }
            for f in received
        ],
        "shared_by_me": [
            {
                "id": s.id,
                "file_id": s.file_id,
                "filename": s.file.filename,
                "file_size": s.file.file_size,
                "shared_with_username": s.shared_with.username,
                "created_at": s.created_at,
                "is_expired": s.file.expiry_at < datetime.datetime.utcnow() if s.file.expiry_at else False
            }
            for s in shares_sent
        ],
        "shared_with_me": [
            {
                "id": s.id,
                "file_id": s.file_id,
                "filename": s.file.filename,
                "file_size": s.file.file_size,
                "shared_by_username": s.shared_by.username,
                "created_at": s.created_at,
                "is_expired": s.file.expiry_at < datetime.datetime.utcnow() if s.file.expiry_at else False
            }
            for s in shares_received
        ]
    }


@router.post("/share", status_code=status.HTTP_201_CREATED)
def share_file(
    request: Request,
    share_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = request.client.host if request.client else "127.0.0.1"
    file_id = share_data.get("file_id")
    shared_with_id = share_data.get("shared_with_id")

    if not file_id or not shared_with_id:
        raise HTTPException(status_code=400, detail="file_id and shared_with_id are required")

    # 1. Fetch original file metadata
    file_record = db.query(File).filter(File.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    # 2. Check ownership (only owner can share)
    if file_record.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the file owner can share this file")

    # 3. Check if target user exists
    target_user = db.query(User).filter(User.id == shared_with_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User to share with not found")

    # 4. Check if already shared
    existing_share = db.query(SharedFile).filter(
        (SharedFile.file_id == file_id) & (SharedFile.shared_with_id == shared_with_id)
    ).first()
    if existing_share:
        return {"message": f"File is already shared with {target_user.username}", "share_id": existing_share.id}

    # 5. Read the owner's encrypted file from disk
    orig_path = get_file_path(file_record.id)
    if not os.path.exists(orig_path):
        raise HTTPException(status_code=404, detail="Encrypted file not found on disk")

    with open(orig_path, "rb") as f:
        orig_ciphertext = f.read()

    # 6. Decrypt file using the owner's details (since Alice is the owner, and originally uploaded it)
    # If it was uploaded for Alice, we decrypt using Alice's keys.
    # If it was uploaded for someone else, the original recipient's private key is used to decrypt.
    # To support zero-trust seamless sharing, we load the recipient's private key (encrypted in DB) 
    # and decrypt it using the master key.
    try:
        original_recipient = db.query(User).filter(User.id == file_record.recipient_id).first()
        plaintext = decrypt_file_for_recipient(
            ciphertext=orig_ciphertext,
            nonce_hex=file_record.nonce,
            signature_hex=file_record.signature,
            ephemeral_pub_pem=file_record.ephemeral_public,
            sender_pub_pem=file_record.owner.public_key,
            recipient_priv_encrypted=original_recipient.private_key_encrypted
        )
    except Exception as e:
        log_security_event(db, "DECRYPTION_FAILED", "HIGH", current_user.id, f"Decryption failed during share processing for file {file_id}: {str(e)}", ip)
        raise HTTPException(status_code=400, detail=f"Failed to decrypt original file for sharing: {str(e)}")

    # 7. Re-encrypt file using target user's public key
    try:
        new_ciphertext, new_nonce, new_signature, new_ephemeral_pub, _ = encrypt_file_for_recipient(
            file_bytes=plaintext,
            recipient_pub_pem=target_user.public_key,
            sender_priv_encrypted=current_user.private_key_encrypted
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cryptographic sharing encryption failed: {str(e)}")

    # 8. Store shared record in DB
    new_share = SharedFile(
        file_id=file_record.id,
        shared_by_id=current_user.id,
        shared_with_id=target_user.id,
        nonce=new_nonce,
        signature=new_signature,
        ephemeral_public=new_ephemeral_pub
    )
    new_share.original_signature = new_signature

    db.add(new_share)
    db.commit()
    db.refresh(new_share)

    # 9. Store the new ciphertext specifically for this recipient
    shared_path = get_file_path(new_share.id, is_shared=True)
    with open(shared_path, "wb") as f:
        f.write(new_ciphertext)

    # Log successful sharing
    log_audit(
        db, 
        current_user.id, 
        "SHARE", 
        f"Shared file '{file_record.filename}' (ID: {file_record.id}) with {target_user.username}", 
        ip
    )

    return {
        "share_id": new_share.id,
        "file_id": file_record.id,
        "shared_with": target_user.username,
        "message": "File shared securely. Recipient-specific ciphertext generated."
    }


@router.get("/metadata/{id}")
def get_file_metadata(
    id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    is_shared_download = id.startswith("share_")
    if is_shared_download:
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared file record not found")
            
        if current_user.id not in [share.shared_by_id, share.shared_with_id]:
            raise HTTPException(status_code=403, detail="Unauthorized access to this shared file")
            
        return {
            "id": id,
            "filename": share.file.filename,
            "file_size": share.file.file_size,
            "owner_username": share.shared_by.username,
            "recipient_username": share.shared_with.username,
            "expiry_at": share.file.expiry_at,
            "sha256_checksum": share.file.sha256_checksum,
        }
    else:
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
            
        if current_user.id not in [file_record.owner_id, file_record.recipient_id]:
            raise HTTPException(status_code=403, detail="Unauthorized access to this file")
            
        return {
            "id": id,
            "filename": file_record.filename,
            "file_size": file_record.file_size,
            "owner_username": file_record.owner.username,
            "recipient_username": file_record.recipient.username,
            "expiry_at": file_record.expiry_at,
            "sha256_checksum": file_record.sha256_checksum,
        }


@router.get("/download/{id}")
def download_file(
    id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Downloads, verifies, and decrypts a file.
    Works for direct files (ID is file UUID) and shared files (ID is formatted as 'share_{id}').
    """
    ip = request.client.host if request.client else "127.0.0.1"
    is_shared_download = id.startswith("share_")
    
    # 1. Load details based on whether it is direct or shared
    if is_shared_download:
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared file record not found")
            
        # Access control: Must be either the person who shared it, or the recipient
        if current_user.id not in [share.shared_by_id, share.shared_with_id]:
            log_security_event(db, "UNAUTHORIZED_ACCESS", "HIGH", current_user.id, f"User tried to download unauthorized shared file {share_id}", ip)
            raise HTTPException(status_code=403, detail="Unauthorized access to this shared file")
            
        file_record = share.file
        nonce = share.nonce
        signature = share.signature
        ephemeral_pub = share.ephemeral_public
        sender_pub_pem = share.shared_by.public_key
        # For decryption, the shared-with recipient's keys are used.
        # If the owner downloads their sent share, we decrypt using the recipient's keys.
        decrypting_user = share.shared_with
        ciphertext_path = get_file_path(share.id, is_shared=True)
    else:
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
            
        # Access control: Must be owner or recipient
        if current_user.id not in [file_record.owner_id, file_record.recipient_id]:
            log_security_event(db, "UNAUTHORIZED_ACCESS", "HIGH", current_user.id, f"User tried to download unauthorized direct file {id}", ip)
            raise HTTPException(status_code=403, detail="Unauthorized access to this file")
            
        nonce = file_record.nonce
        signature = file_record.signature
        ephemeral_pub = file_record.ephemeral_public
        sender_pub_pem = file_record.owner.public_key
        # The direct recipient's private key is used for decryption
        decrypting_user = file_record.recipient
        ciphertext_path = get_file_path(file_record.id)

    # 2. Check Expiry
    if file_record.expiry_at and file_record.expiry_at < datetime.datetime.utcnow():
        log_security_event(db, "EXPIRED_ACCESS", "LOW", current_user.id, f"Attempted to access expired file {file_record.id}", ip)
        raise HTTPException(status_code=410, detail="This file has expired and is no longer available")

    # 3. Check if file is already deleted (e.g. self-destructed one-time download)
    if not os.path.exists(ciphertext_path):
        raise HTTPException(status_code=404, detail="File ciphertext not found on server (may have self-destructed)")

    # 4. Read ciphertext
    with open(ciphertext_path, "rb") as f:
        ciphertext = f.read()

    # 5. Perform Cryptographic Verification and Decryption
    try:
        plaintext = decrypt_file_for_recipient(
            ciphertext=ciphertext,
            nonce_hex=nonce,
            signature_hex=signature,
            ephemeral_pub_pem=ephemeral_pub,
            sender_pub_pem=sender_pub_pem,
            recipient_priv_encrypted=decrypting_user.private_key_encrypted
        )
    except InvalidSignature:
        # FAILED ECDSA VERIFICATION (SIGNATURE FORGERY ATTEMPT!)
        log_security_event(
            db,
            "SIGNATURE_FORGERY",
            "CRITICAL",
            current_user.id,
            f"Signature verification FAILED for file '{file_record.filename}' (ID: {file_record.id}). Potential forgery/MITM attack!",
            ip
        )
        raise HTTPException(
            status_code=400,
            detail="ECDSA Digital Signature verification failed! The file signature has been forged or altered."
        )
    except InvalidTag:
        # FAILED AES-GCM AUTHENTICATION (TAMPERING ATTEMPT!)
        log_security_event(
            db,
            "TAMPERING_ATTEMPT",
            "CRITICAL",
            current_user.id,
            f"AES-GCM decryption FAILED for file '{file_record.filename}' (ID: {file_record.id}). Ciphertext has been modified!",
            ip
        )
        raise HTTPException(
            status_code=400,
            detail="AES-GCM Authentication failed! The file ciphertext has been tampered with or corrupted on the server."
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # 6. Check for One-Time Download self-destruction
    if not is_shared_download and file_record.one_time_download:
        file_record.is_downloaded = True
        db.commit()
        # Delete file from disk!
        try:
            os.remove(ciphertext_path)
            # Also clean up shares for this file since original is destroyed
            shares = db.query(SharedFile).filter(SharedFile.file_id == file_record.id).all()
            for s in shares:
                sh_path = get_file_path(s.id, is_shared=True)
                if os.path.exists(sh_path):
                    os.remove(sh_path)
                db.delete(s)
            db.commit()
        except Exception:
            pass
        log_audit(db, current_user.id, "SELF_DESTRUCT", f"One-time download triggered self-destruction of file '{file_record.filename}'", ip)
    else:
        log_audit(db, current_user.id, "DOWNLOAD", f"Successfully downloaded and verified '{file_record.filename}'", ip)

    # 7. Stream decrypted plaintext back to recipient
    response_stream = BytesIO(plaintext)
    
    # We set custom headers so the frontend knows the signature was verified successfully!
    headers = {
        "Content-Disposition": f"attachment; filename={file_record.filename}",
        "X-Signature-Verification": "SUCCESS",
        "X-Integrity-Checksum": file_record.sha256_checksum,
        "Access-Control-Expose-Headers": "Content-Disposition, X-Signature-Verification, X-Integrity-Checksum"
    }

    return StreamingResponse(
        response_stream,
        media_type="application/octet-stream",
        headers=headers
    )


@router.delete("/{id}")
def delete_file(
    id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = request.client.host if request.client else "127.0.0.1"
    is_shared = id.startswith("share_")

    if is_shared:
        # Revoke/Delete a specific share
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared record not found")

        # Only owner (shared_by) or recipient (shared_with) can revoke
        if current_user.id not in [share.shared_by_id, share.shared_with_id]:
            raise HTTPException(status_code=403, detail="Unauthorized to delete this share")

        sh_path = get_file_path(share.id, is_shared=True)
        if os.path.exists(sh_path):
            try:
                os.remove(sh_path)
            except Exception:
                pass

        filename = share.file.filename
        shared_with = share.shared_with.username
        
        db.delete(share)
        db.commit()

        log_audit(db, current_user.id, "REVOKE_SHARE", f"Revoked share of '{filename}' with {shared_with}", ip)
        return {"message": "Shared file access revoked successfully"}

    else:
        # Delete original file
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")

        if file_record.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the file owner can delete this file")

        # 1. Delete original file on disk
        ciphertext_path = get_file_path(file_record.id)
        if os.path.exists(ciphertext_path):
            try:
                os.remove(ciphertext_path)
            except Exception:
                pass

        # 2. Delete all recipient shares on disk
        shares = db.query(SharedFile).filter(SharedFile.file_id == file_record.id).all()
        for s in shares:
            sh_path = get_file_path(s.id, is_shared=True)
            if os.path.exists(sh_path):
                try:
                    os.remove(sh_path)
                except Exception:
                    pass

        filename = file_record.filename
        
        db.delete(file_record)
        db.commit()

        log_audit(db, current_user.id, "DELETE_FILE", f"Deleted file '{filename}' and all its shared copies.", ip)
        return {"message": "File and all associated shares deleted successfully"}
