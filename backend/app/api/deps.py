"""Shared FastAPI dependencies."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.files.service import FileService
from app.network.service import NetworkService
from app.services.intel_service import IntelService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def get_intel_service(request: Request) -> IntelService:
    return request.app.state.intel_service


def get_file_service(request: Request) -> FileService:
    return request.app.state.file_service


def get_network_service(request: Request) -> NetworkService:
    return request.app.state.network_service


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSession = Annotated[Session, Depends(get_db)]
IntelServiceDep = Annotated[IntelService, Depends(get_intel_service)]
FileServiceDep = Annotated[FileService, Depends(get_file_service)]
NetworkServiceDep = Annotated[NetworkService, Depends(get_network_service)]
