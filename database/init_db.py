"""
Fast, dev-only way to create all tables directly from the SQLAlchemy
models -- no migration history, just Base.metadata.create_all().

Use this for a quick local sanity check that DATABASE_URL is correct and
you can reach Supabase. For anything shared with the team (or once the
schema needs to evolve), use Alembic instead:

    alembic upgrade head

Running this against a database that already has an Alembic history is
safe (create_all skips existing tables) but the two won't know about each
other, so don't mix them on the same database long-term.
"""

from database.connection import Base, engine
from database import models  # noqa: F401  (registers models on Base.metadata)


def main():
    print(f"Connecting to: {engine.url.render_as_string(hide_password=True)}")
    Base.metadata.create_all(bind=engine)
    print("Tables created (or already existed): scans, resources, findings")


if __name__ == "__main__":
    main()
