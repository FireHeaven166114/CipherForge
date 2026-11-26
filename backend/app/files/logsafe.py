"""Keep share tokens out of logs.

A share token is a bearer secret, and it travels in the URL path (``/api/v1/shares/<token>``).
The request-logging middleware records the path of every request, so without this filter each
download would leave a usable link in the logs. The filter masks the path segment that follows
``/shares/`` or ``/share/`` on the loggers that record request paths.
"""

import logging
import re

REDACTED = "[redacted]"

_TOKEN_SEGMENT = re.compile(r"(?<=/shares/)[^/?#\s\"']+|(?<=/share/)[^/?#\s\"']+")
_LOGGERS = ("cipherforge.http", "uvicorn.access")


def mask_share_tokens(text: str) -> str:
    return _TOKEN_SEGMENT.sub(REDACTED, text) if "/share" in text else text


class ShareTokenFilter(logging.Filter):
    """Masks tokens in a record's ``path`` extra and in string arguments (uvicorn access log)."""

    def filter(self, record: logging.LogRecord) -> bool:
        path = getattr(record, "path", None)
        if isinstance(path, str):
            record.path = mask_share_tokens(path)
        if isinstance(record.args, tuple):
            record.args = tuple(
                mask_share_tokens(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        return True


def install_share_token_filter() -> None:
    """Attach the filter to the request-path loggers (idempotent)."""
    for name in _LOGGERS:
        target = logging.getLogger(name)
        if not any(isinstance(existing, ShareTokenFilter) for existing in target.filters):
            target.addFilter(ShareTokenFilter())
