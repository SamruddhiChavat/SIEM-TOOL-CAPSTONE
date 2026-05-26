from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from db.database import get_db
from db.models import User, AuditLog
from .jwt_handler import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
        
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
        
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    
    if user is None or not user.is_active:
        raise credentials_exception
        
    return user

def require_role(roles: list[str]):
    """Dependency that checks if the current user has one of the required roles."""
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions to perform this action"
            )
        return current_user
    return role_checker

# Pre-defined dependencies for common roles
require_admin = require_role(["admin"])
require_analyst = require_role(["admin", "analyst"])

async def log_audit(db: AsyncSession, username: str, action: str, resource: str, target_id: str = None, ip_address: str = None, details: dict = None):
    """Log an action to the audit logs."""
    import uuid
    log = AuditLog(
        id=str(uuid.uuid4()),
        username=username,
        action=action,
        resource=resource,
        target_id=target_id,
        ip_address=ip_address,
        details=details or {}
    )
    db.add(log)
    await db.commit()
