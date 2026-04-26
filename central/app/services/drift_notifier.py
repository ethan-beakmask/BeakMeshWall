"""Drift notification.

Sends alerts via SMTP if configured; falls back to writing the message to
BMW_NOTIFY_LOG_PATH so the operator can still see what happened in dev.

See docs/ROADMAP-CONFIG-MANAGEMENT.md section 4.4.
"""
import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app


def send_drift_alert(node, event, missing: list[str], extra: list[str]) -> None:
    subject = f"[BeakMeshWall] drift detected on {node.hostname} ({node.ip_address})"
    body = _compose_body(node, event, missing, extra)

    cfg = current_app.config
    smtp_host = cfg.get("SMTP_HOST")
    notify_to = cfg.get("NOTIFY_TO")

    if smtp_host and notify_to:
        _send_smtp(cfg, subject, body, notify_to)
    else:
        _write_log_fallback(cfg.get("NOTIFY_LOG_PATH"), subject, body)


def _compose_body(node, event, missing: list[str], extra: list[str]) -> str:
    lines = [
        f"Node:        {node.hostname} ({node.ip_address})",
        f"Subsystem:   {event.subsystem}",
        f"Detected at: {event.detected_at.isoformat() if event.detected_at else '-'}",
        f"Policy:      {event.policy_applied}",
        "",
        f"Missing in actual ({len(missing)}):",
    ]
    if missing:
        lines += [f"  - BMW-ID={fp}" for fp in missing]
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"Extra in actual ({len(extra)}):")
    if extra:
        lines += [f"  - BMW-ID={fp}" for fp in extra]
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("See central/app/services/drift_detector.py and ")
    lines.append("docs/ROADMAP-CONFIG-MANAGEMENT.md section 4 for handling logic.")
    return "\n".join(lines)


def _send_smtp(cfg, subject: str, body: str, to_addr: str) -> None:
    msg = EmailMessage()
    msg["From"] = cfg.get("SMTP_FROM") or "beakmeshwall@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    host = cfg["SMTP_HOST"]
    port = int(cfg.get("SMTP_PORT") or 25)

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if cfg.get("SMTP_USER"):
            smtp.starttls()
            smtp.login(cfg["SMTP_USER"], cfg.get("SMTP_PASSWORD") or "")
        smtp.send_message(msg)


def _write_log_fallback(path: str | None, subject: str, body: str) -> None:
    if not path:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"=== {stamp} ===\n")
        f.write(f"Subject: {subject}\n")
        f.write(body)
        f.write("\n\n")
