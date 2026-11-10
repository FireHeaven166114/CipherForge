"""Alembic environment.

The database URL comes from the application settings (``DATABASE_URL``).
Programmatic callers (tests) can instead hand over an open connection via
``config.attributes["connection"]``.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine, pool

from app.core.config import get_settings
from app.models import Base

config = context.config
target_metadata = Base.metadata

injected_connection: Connection | None = config.attributes.get("connection")

if config.config_file_name is not None and injected_connection is None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most things in place; batch mode keeps migrations portable.
        render_as_batch=connection.dialect.name == "sqlite",
    )


def run_migrations_offline() -> None:
    context.configure(
        url=get_settings().database_url.get_secret_value(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    if injected_connection is not None:
        _run_with(injected_connection)
        return

    engine = create_engine(get_settings().database_url.get_secret_value(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        _run_with(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
