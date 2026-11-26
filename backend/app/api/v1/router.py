from fastapi import APIRouter

from app.api.v1 import files, intel, me, network

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(me.router)
api_router.include_router(intel.router)
api_router.include_router(network.router)
api_router.include_router(files.router)
api_router.include_router(files.public_router)
