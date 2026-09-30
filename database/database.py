from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "firewall.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                intent TEXT,
                intent_category TEXT,
                intent_confidence REAL,
                semantic_label TEXT,
                malicious_probability REAL,
                rule_matched INTEGER,
                rule_severity TEXT,
                retrieval_matched INTEGER,
                retrieval_similarity REAL,
                llm_allowed INTEGER,
                processing_time_ms REAL,
                prompt_hash TEXT,
                prompt_content TEXT,
                result_json TEXT NOT NULL
            )
            """
        )

        connection.commit()
