import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from database.database import get_connection


def create_request_id() -> str:
    return str(uuid.uuid4())


def hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def save_security_result(
    result: Any,
    processing_time_ms: float = 0.0,
    log_prompt_content: bool = False,
) -> str:

    request_id = create_request_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    result_dict = result.to_dict()

    semantic = result_dict.get("semantic") or {}
    rules = result_dict.get("rules") or {}
    intent = result_dict.get("intent") or {}
    retrieval = result_dict.get("retrieval") or {}
    metadata = result_dict.get("metadata") or {}

    prompt = result_dict.get("original_prompt", "")

    prompt_hash = hash_prompt(prompt)
    prompt_content = prompt if log_prompt_content else None

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO security_events (
                request_id,
                timestamp,
                decision,
                risk_level,
                risk_score,
                intent,
                intent_category,
                intent_confidence,
                semantic_label,
                malicious_probability,
                rule_matched,
                rule_severity,
                retrieval_matched,
                retrieval_similarity,
                llm_allowed,
                processing_time_ms,
                prompt_hash,
                prompt_content,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                timestamp,
                result_dict.get("decision"),
                result_dict.get("risk_level"),
                result_dict.get("risk_score", 0.0),
                intent.get("intent"),
                intent.get("category"),
                intent.get("confidence"),
                semantic.get("label"),
                semantic.get("malicious_probability"),
                int(bool(rules.get("matched"))),
                rules.get("severity"),
                int(bool(retrieval.get("matched"))),
                retrieval.get("similarity"),
                int(bool(metadata.get("llm_allowed"))),
                processing_time_ms,
                prompt_hash,
                prompt_content,
                json.dumps(result_dict, ensure_ascii=False),
            ),
        )

        connection.commit()

    return request_id
