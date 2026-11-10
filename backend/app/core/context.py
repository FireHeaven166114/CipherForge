"""Request-scoped context shared by middleware and logging."""

from contextvars import ContextVar

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
