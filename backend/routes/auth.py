import datetime
import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from backend.database.session import get_db
from backend.database.models import User, AuditLog, SecurityEvent
from backend.services.crypto_service import generate_user_keypair, encrypt_with_master_key

router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


# --- PASSWORDS HASHING HELPERS ---

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# --- JWT TOKEN HELPERS ---

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- GET CURRENT USER DEPENDENCY ---

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user


# --- AUDIT & SECURITY LOG HELPERS ---

def log_audit(db: Session, user_id: int, action: str, details: str, ip: str):
    log = AuditLog(
        user_id=user_id,
        action_encrypted=encrypt_with_master_key(action),
        details_encrypted=encrypt_with_master_key(details),
        ip_address_encrypted=encrypt_with_master_key(ip)
    )
    db.add(log)
    db.commit()


def log_security_event(db: Session, event_type: str, severity: str, user_id: int, details: str, ip: str):
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        details=details,
        ip_address=ip
    )
    db.add(event)
    db.commit()


# --- ROUTE HANDLERS ---

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: dict, request: Request, db: Session = Depends(get_db)):
    username = user_data.get("username")
    email = user_data.get("email")
    password = user_data.get("password")
    ip = request.client.host if request.client else "127.0.0.1"

    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Missing required registration fields")

    # Check unique
    existing_user = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    # Cryptographic Setup: Generate long-term ECC keypair
    public_key_pem, private_key_encrypted = generate_user_keypair()
    
    # Hash password
    pwd_hash = hash_password(password)

    new_user = User(
        username=username,
        email=email,
        password_hash=pwd_hash,
        public_key=public_key_pem,
        private_key_encrypted=private_key_encrypted
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit(db, new_user.id, "REGISTER", f"User {username} registered successfully.", ip)

    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "public_key": new_user.public_key,
        "message": "User registered successfully with ECC keys generated."
    }


@router.post("/login")
def login(login_data: dict, request: Request, db: Session = Depends(get_db)):
    username = login_data.get("username")
    password = login_data.get("password")
    ip = request.client.host if request.client else "127.0.0.1"

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    user = db.query(User).filter(User.username == username).first()
    
    if not user or not verify_password(password, user.password_hash):
        # Log intrusion attempt!
        log_security_event(
            db, 
            "INVALID_LOGIN", 
            "MEDIUM", 
            user.id if user else None, 
            f"Failed login attempt for username: {username}", 
            ip
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Generate JWT
    access_token = create_access_token(data={"sub": str(user.id)})
    
    log_audit(db, user.id, "LOGIN", f"User {username} logged in successfully.", ip)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "public_key": user.public_key
        }
    }
