"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[str, datetime, float]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = request_id if request_id is not None else user_id
        self._open[key] = (text, datetime.now(timezone.utc), perf_counter())

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = request_id if request_id is not None else user_id
        pending = self._open.pop(key, None)
        latency = perf_counter() - pending[2] if pending is not None else None
        log_entry = {
            "user_id": user_id,
            "request_id": request_id,
            "input_text": pending[0] if pending is not None else None,
            "started_at": pending[1].isoformat() if pending is not None else None,
            "output_text": text,
            "blocked": blocked,
            "layer": layer,
            "latency": latency,
            "latency_ms": latency * 1000 if latency is not None else None,
            "timestamp": utc_now_iso(),
        }
        self.logs.append(log_entry)


    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        filepath = Path(filepath if filepath else default_audit_log_path())
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=4, ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
