"""Authorization roles.

The values are the Microsoft Entra *app role values* the API expects in the
``roles`` claim of an access token. Entra does not allow spaces in a role value,
so the display name "Security Analyst" maps to ``SecurityAnalyst``.
"""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "Admin"
    SECURITY_ANALYST = "SecurityAnalyst"
    USER = "User"

    @classmethod
    def parse(cls, raw: str) -> "Role | None":
        """Return the matching role (case-insensitive, ignoring spaces/underscores) or None."""
        normalised = raw.strip().replace(" ", "").replace("_", "").lower()
        for role in cls:
            if role.value.lower() == normalised:
                return role
        return None
