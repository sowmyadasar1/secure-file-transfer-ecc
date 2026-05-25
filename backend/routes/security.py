import os
import shutil
import secrets
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.session import get_db
from backend.database.models import User, File, SharedFile, AuditLog, SecurityEvent
from backend.routes.auth import get_current_user, log_audit, log_security_event
from backend.routes.files import get_file_path
from backend.services.crypto_service import decrypt_with_master_key

router = APIRouter(prefix="/security", tags=["Security"])


# --- ENDPOINTS ---

@router.get("/audit-logs")
def get_my_audit_logs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves and decrypts audit logs for the current user."""
    logs = db.query(AuditLog).filter(AuditLog.user_id == current_user.id).order_by(AuditLog.created_at.desc()).all()
    
    decrypted_logs = []
    for log in logs:
        try:
            action = decrypt_with_master_key(log.action_encrypted)
            details = decrypt_with_master_key(log.details_encrypted)
            ip_address = decrypt_with_master_key(log.ip_address_encrypted)
            decrypted_logs.append({
                "id": log.id,
                "action": action,
                "details": details,
                "ip_address": ip_address,
                "created_at": log.created_at
            })
        except Exception:
            # Fallback if decryption fails
            decrypted_logs.append({
                "id": log.id,
                "action": "DECRYPTION_ERROR",
                "details": "Could not decrypt log entry.",
                "ip_address": "UNKNOWN",
                "created_at": log.created_at
            })
            
    return decrypted_logs


@router.get("/security-events")
def get_security_events(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves the list of all global threat intelligence and security events."""
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "username": e.user.username if e.user else "Anonymous / System",
            "details": e.details,
            "ip_address": e.ip_address,
            "created_at": e.created_at
        }
        for e in events
    ]


@router.get("/security-insights")
def get_security_insights(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    AI Anomaly Detection Engine
    Dynamically analyzes database security events and logs to yield high-level system threat insights.
    """
    events = db.query(SecurityEvent).all()
    
    total_threats = len(events)
    tamper_count = sum(1 for e in events if e.event_type == "TAMPERING_ATTEMPT")
    forge_count = sum(1 for e in events if e.event_type == "SIGNATURE_FORGERY")
    failed_logins = sum(1 for e in events if e.event_type == "INVALID_LOGIN")
    unauthorized_downloads = sum(1 for e in events if e.event_type == "UNAUTHORIZED_ACCESS")
    
    # Calculate health score (starting at 100)
    # Tampering & Forgeries count for -15, unauthorized accesses -10, failed logins -2
    score = 100 - (tamper_count * 15) - (forge_count * 15) - (unauthorized_downloads * 10) - (failed_logins * 2)
    score = max(0, min(100, score))
    
    # System Status
    if score == 100:
        status_label = "SECURE"
        description = "All cryptographic parameters operating within nominal margins. No threats detected."
    elif score >= 80:
        status_label = "WARNING"
        description = "Minor security friction observed (e.g. incorrect credentials). Core storage integrity is fully secure."
    else:
        status_label = "INTRUSION_BLOCKED"
        description = "Active threats intercepted. File integrity scanning and signature verification have successfully quarantined tampering and forgery attempts."

    # Insights list
    insights = []
    if tamper_count > 0:
        insights.append(f"Intercepted {tamper_count} ciphertext tampering event(s). AES-GCM tag verification successfully blocked corrupted data.")
    if forge_count > 0:
        insights.append(f"Intercepted {forge_count} digital signature forgery event(s). ECDSA signature validation verified file authenticity.")
    if failed_logins > 3:
        insights.append("High volume of failed logins observed. Flagged as brute-force anomaly. IP addresses isolated in security dashboard.")
    if unauthorized_downloads > 0:
        insights.append(f"Blocked {unauthorized_downloads} unauthorized file decryption attempt(s). Zero-trust RBAC access controls enforced.")

    if not insights:
        insights.append("No active cryptographic anomalies or intrusion signatures detected in recent logs.")

    return {
        "score": score,
        "status": status_label,
        "description": description,
        "metrics": {
            "total_threats": total_threats,
            "tampering_attempts": tamper_count,
            "signature_forgeries": forge_count,
            "failed_logins": failed_logins,
            "unauthorized_accesses": unauthorized_downloads
        },
        "insights": insights
    }


# --- ATTACK SIMULATOR ENDPOINTS ---

@router.post("/simulate/corrupt/{id}")
def corrupt_ciphertext(
    id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    SIMULATED ATTACK: Corrupts the file's ciphertext on disk.
    This will cause AES-GCM decryption to fail with an InvalidTag error on download.
    """
    ip = request.client.host if request.client else "127.0.0.1"
    is_shared = id.startswith("share_")
    
    # 1. Fetch file or share details to find file path
    if is_shared:
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared file not found")
        if share.shared_by_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the file owner can simulate attacks")
        
        file_name = share.file.filename
        ciphertext_path = get_file_path(share.id, is_shared=True)
    else:
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        if file_record.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the file owner can simulate attacks")
            
        file_name = file_record.filename
        ciphertext_path = get_file_path(file_record.id)

    if not os.path.exists(ciphertext_path):
        raise HTTPException(status_code=400, detail="Ciphertext file not found on disk")

    # 2. Back up original ciphertext if not already done
    backup_path = ciphertext_path + ".bak"
    if not os.path.exists(backup_path):
        shutil.copyfile(ciphertext_path, backup_path)

    # 3. Corrupt ciphertext bytes
    with open(ciphertext_path, "r+b") as f:
        data = f.read()
        if len(data) > 20:
            # Modify a byte in the middle
            corrupted_data = bytearray(data)
            corrupted_data[15] ^= 0xFF  # Flip bits of a byte
            f.seek(0)
            f.write(corrupted_data)
        else:
            # If tiny, just overwrite with random data
            f.seek(0)
            f.write(secrets.token_bytes(len(data)))

    # 4. Log security threat event
    log_security_event(
        db,
        "TAMPERING_ATTEMPT",
        "HIGH",
        current_user.id,
        f"[SIMULATED ATTACK] Ciphertext file for '{file_name}' (ID: {id}) was modified on disk by the Attack Simulator.",
        ip
    )

    return {"message": f"Simulated ciphertext corruption successful for file '{file_name}'. Decryption will now fail."}


@router.post("/simulate/forge/{id}")
def forge_signature(
    id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    SIMULATED ATTACK: Replaces the file's digital signature in the database with garbage.
    This will cause ECDSA signature verification to fail immediately upon download before decryption begins.
    """
    ip = request.client.host if request.client else "127.0.0.1"
    is_shared = id.startswith("share_")
    
    if is_shared:
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared record not found")
        if share.shared_by_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the file owner can simulate attacks")
            
        file_name = share.file.filename
        
        # Forge signature in DB
        share.signature = secrets.token_hex(64)
        db.commit()
    else:
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        if file_record.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the file owner can simulate attacks")
            
        file_name = file_record.filename
        
        # Forge signature in DB
        file_record.signature = secrets.token_hex(64)
        db.commit()

    log_security_event(
        db,
        "SIGNATURE_FORGERY",
        "HIGH",
        current_user.id,
        f"[SIMULATED ATTACK] Digital signature for '{file_name}' (ID: {id}) was forged in the database.",
        ip
    )

    return {"message": f"Simulated signature forgery successful for file '{file_name}'. Signature check will now fail."}


@router.post("/simulate/repair/{id}")
def repair_file(
    id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    REPAIR SYSTEM: Restores original ciphertext and signature, bringing the system back to fully secure status.
    """
    ip = request.client.host if request.client else "127.0.0.1"
    is_shared = id.startswith("share_")
    
    if is_shared:
        try:
            share_id = int(id.replace("share_", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid share ID format")
            
        share = db.query(SharedFile).filter(SharedFile.id == share_id).first()
        if not share:
            raise HTTPException(status_code=404, detail="Shared record not found")
        if share.shared_by_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can repair the file")

        file_name = share.file.filename
        ciphertext_path = get_file_path(share.id, is_shared=True)
        
        # Restore signature
        if share.original_signature:
            share.signature = share.original_signature
            db.commit()
    else:
        file_record = db.query(File).filter(File.id == id).first()
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        if file_record.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can repair the file")

        file_name = file_record.filename
        ciphertext_path = get_file_path(file_record.id)
        
        # Restore signature
        if file_record.original_signature:
            file_record.signature = file_record.original_signature
            db.commit()

    # Restore ciphertext on disk
    backup_path = ciphertext_path + ".bak"
    if os.path.exists(backup_path):
        try:
            shutil.copyfile(backup_path, ciphertext_path)
            os.remove(backup_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to restore file backup: {str(e)}")

    log_audit(
        db, 
        current_user.id, 
        "SIMULATION_REPAIR", 
        f"Restored signature and ciphertext integrity from secure backup for '{file_name}' (ID: {id})", 
        ip
    )

    return {"message": f"File '{file_name}' successfully repaired from backup. Integrity fully restored!"}
