"""ORM models. Import every model module here so Alembic sees its metadata."""

from app.models.base import Base

__all__ = ["Base"]
