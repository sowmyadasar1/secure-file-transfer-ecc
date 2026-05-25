from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database.session import get_db
from backend.database.models import User
from backend.routes.auth import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("")
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves all registered users and their public keys, excluding the current logged-in user."""
    users = db.query(User).filter(User.id != current_user.id).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "public_key": u.public_key
        }
        for u in users
    ]
