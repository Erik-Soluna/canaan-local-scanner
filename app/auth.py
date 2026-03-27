from __future__ import annotations

import os
from typing import Optional

from fastapi import Request
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import User


# Use a pure-Python hash (no native bcrypt backend dependency issues).
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def get_session_user_id(request: Request) -> Optional[int]:
    user_id = None
    try:
        user_id = request.session.get("user_id")
    except Exception:
        user_id = None
    if user_id is None:
        return None
    try:
        return int(user_id)
    except (TypeError, ValueError):
        return None


def get_current_user(db: Session, request: Request) -> Optional[User]:
    user_id = get_session_user_id(request)
    if not user_id:
        return None
    return db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()


def create_initial_admin_if_missing(db: Session) -> None:
    # We create an admin automatically on first run so the app is usable.
    # For real deployments, set `ADMIN_USERNAME`/`ADMIN_PASSWORD`.
    existing_admin = db.execute(select(User).where(User.is_admin == True)).scalar_one_or_none()  # noqa: E712
    if existing_admin is not None:
        return

    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "admin")

    if not username or not password:
        raise RuntimeError(
            "Admin user missing and ADMIN_USERNAME/ADMIN_PASSWORD not provided."
        )

    admin = User(username=username, password_hash=hash_password(password), is_admin=True)
    db.add(admin)
    db.commit()


def require_admin(user: User) -> None:
    if not user.is_admin:
        raise PermissionError("Admin privileges required.")

