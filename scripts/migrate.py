"""Simple migration helper to create/recreate database tables."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import engine, Base, init_db
from backend.models import Indicator, FeedRun, AnomalyFlag, MLPrediction, ScanHistory


def create_tables():
    """Create all tables."""
    init_db()
    print("All tables created successfully.")


def drop_tables():
    """Drop all tables (DESTRUCTIVE)."""
    confirm = input("This will DROP all tables. Type 'yes' to confirm: ")
    if confirm.strip().lower() == "yes":
        Base.metadata.drop_all(bind=engine)
        print("All tables dropped.")
    else:
        print("Cancelled.")


def reset_tables():
    """Drop and recreate all tables (DESTRUCTIVE)."""
    confirm = input("This will RESET the database. Type 'yes' to confirm: ")
    if confirm.strip().lower() == "yes":
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        print("Database reset complete.")
    else:
        print("Cancelled.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/migrate.py [create|drop|reset]")
        sys.exit(1)

    action = sys.argv[1]
    if action == "create":
        create_tables()
    elif action == "drop":
        drop_tables()
    elif action == "reset":
        reset_tables()
    else:
        print(f"Unknown action: {action}. Use create, drop, or reset.")
