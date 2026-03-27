from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def get_db_path() -> Path:
    # Store alongside the project for easy deployment.
    default_path = Path(__file__).resolve().parents[1] / "canaan_scanner.sqlite"
    return Path(os.getenv("DB_PATH", str(default_path)))


def create_session_factory():
    db_path = get_db_path()
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False)


ENGINE, SessionLocal = create_session_factory()

