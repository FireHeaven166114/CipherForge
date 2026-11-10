from typing import Literal

from pydantic import BaseModel


class MeResponse(BaseModel):
    subject: str
    name: str | None
    roles: list[str]
    auth_mode: Literal["dev", "entra"]
