#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BeakMeshWall -- Email Report Receiver

Reads encrypted agent reports from Gmail via IMAP, decrypts them,
and writes the data into the database using the same logic as the
HTTP /api/v1/agent/report endpoint.

Usage:
  email_receiver.py                     Show usage
  email_receiver.py --once              Process pending emails once and exit
  email_receiver.py --daemon            Run continuously (check every --interval seconds)
  email_receiver.py --daemon --interval 60

Environment variables (or pass via arguments):
  BMW_EMAIL_IMAP_HOST       IMAP server (default: imap.gmail.com)
  BMW_EMAIL_IMAP_PORT       IMAP port (default: 993)
  BMW_EMAIL_USERNAME        Gmail address
  BMW_EMAIL_APP_PASSWORD    Gmail App Password
  BMW_EMAIL_ENCRYPT_KEY     AES-256 key (64 hex chars, must match agent config)
  BMW_DATABASE_URI          PostgreSQL connection string
"""

import argparse
import base64
import email
import imaplib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path for app imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash

from app import create_app
from app.extensions import db
from app.models.node import Node

logger = logging.getLogger("bmw_email_receiver")


def decrypt_report(raw: bytes, hex_key: str) -> dict:
    """Decrypt an AES-256-GCM encrypted report from raw bytes.

    The raw payload is: nonce_12bytes + ciphertext + tag_16bytes
    This matches the Go crypto.Encrypt() output.
    Accepts either raw bytes or base64-encoded string.
    """
    if isinstance(raw, str):
        raw = base64.b64decode(raw)

    key = bytes.fromhex(hex_key)
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    if len(raw) < 12:
        raise ValueError("Encrypted data too short")

    nonce = raw[:12]
    ciphertext = raw[12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)


def process_envelope(envelope: dict) -> str:
    """Process a decrypted report envelope and write to DB.

    Returns a status string for logging.
    """
    hostname = envelope.get("hostname", "")
    token = envelope.get("token", "")
    report_ts = envelope.get("timestamp", "")
    report_data = envelope.get("report", {})

    if not hostname or not token:
        return f"SKIP: missing hostname or token"

    # Find node by token verification (same logic as require_agent_token)
    nodes = Node.query.filter(Node.status != "pending").all()
    target_node = None
    for node in nodes:
        if node.token_hash and check_password_hash(node.token_hash, token):
            target_node = node
            break

    if not target_node:
        return f"SKIP: no matching node for hostname={hostname}"

    # Update node state (same logic as agent_report endpoint)
    now = datetime.now(timezone.utc)
    target_node.last_seen_at = now

    state = {}
    if target_node.config_json:
        try:
            state = json.loads(target_node.config_json)
        except (json.JSONDecodeError, TypeError):
            state = {}

    for key in ("fw_state", "nginx_state", "service_state", "system_info"):
        if key in report_data:
            state[key] = report_data[key]

    # Add email transport metadata
    state["_email_received_at"] = now.isoformat()
    state["_email_report_ts"] = report_ts

    target_node.config_json = json.dumps(state)
    db.session.commit()

    return f"OK: node={target_node.id} hostname={hostname} ts={report_ts}"


def fetch_and_process(imap_host: str, imap_port: int, username: str,
                      app_password: str, encrypt_key: str) -> int:
    """Connect to Gmail IMAP, fetch BMW report emails, process them.

    Returns the number of emails processed.
    """
    conn = imaplib.IMAP4_SSL(imap_host, imap_port)
    conn.login(username, app_password)
    conn.select("INBOX")

    # Search for BMW report emails.
    # Use a custom label/flag instead of UNSEEN because Gmail marks
    # self-sent emails as read automatically (same sender/receiver).
    # We use the UNFLAGGED filter: processed emails get flagged.
    status, msg_ids = conn.search(None, '(UNFLAGGED SUBJECT "[BMW-REPORT]")')
    if status != "OK" or not msg_ids[0]:
        conn.logout()
        return 0

    ids = msg_ids[0].split()
    processed = 0

    for msg_id in ids:
        try:
            status, msg_data = conn.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            subject = msg.get("Subject", "")

            # Find the .enc attachment
            encrypted_payload = None
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename() or ""
                    if filename.endswith(".enc"):
                        encrypted_payload = part.get_payload(decode=True)
                        break

            if not encrypted_payload:
                logger.warning("No .enc attachment in email: %s", subject)
                conn.store(msg_id, "+FLAGS", "\\Flagged")
                continue

            # get_payload(decode=True) already decodes Content-Transfer-Encoding
            # (base64), giving us raw bytes: nonce + ciphertext + tag.
            envelope = decrypt_report(encrypted_payload, encrypt_key)
            result = process_envelope(envelope)
            logger.info("Processed %s -> %s", subject, result)

            # Flag as processed to prevent re-processing
            conn.store(msg_id, "+FLAGS", "\\Flagged")
            processed += 1

        except Exception as e:
            logger.error("Failed to process email %s: %s", msg_id, e)
            # Flag to prevent infinite retry
            conn.store(msg_id, "+FLAGS", "\\Flagged")

    conn.logout()
    return processed


def main():
    parser = argparse.ArgumentParser(
        description="BeakMeshWall Email Report Receiver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--once", action="store_true",
                        help="Process pending emails once and exit")
    parser.add_argument("--daemon", action="store_true",
                        help="Run continuously")
    parser.add_argument("--interval", type=int, default=60,
                        help="Check interval in seconds (default: 60)")
    parser.add_argument("--imap-host", default=os.environ.get("BMW_EMAIL_IMAP_HOST", "imap.gmail.com"))
    parser.add_argument("--imap-port", type=int, default=int(os.environ.get("BMW_EMAIL_IMAP_PORT", "993")))
    parser.add_argument("--username", default=os.environ.get("BMW_EMAIL_USERNAME", ""))
    parser.add_argument("--app-password", default=os.environ.get("BMW_EMAIL_APP_PASSWORD", ""))
    parser.add_argument("--encrypt-key", default=os.environ.get("BMW_EMAIL_ENCRYPT_KEY", ""))

    args = parser.parse_args()

    if not args.once and not args.daemon:
        parser.print_help()
        sys.exit(0)

    # Validate required params
    missing = []
    if not args.username:
        missing.append("--username or BMW_EMAIL_USERNAME")
    if not args.app_password:
        missing.append("--app-password or BMW_EMAIL_APP_PASSWORD")
    if not args.encrypt_key:
        missing.append("--encrypt-key or BMW_EMAIL_ENCRYPT_KEY")
    if missing:
        print(f"ERROR: Missing required parameters: {', '.join(missing)}")
        sys.exit(1)

    if len(args.encrypt_key) != 64:
        print("ERROR: encrypt_key must be 64 hex chars (32 bytes for AES-256)")
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    app = create_app()

    if args.once:
        with app.app_context():
            count = fetch_and_process(
                args.imap_host, args.imap_port,
                args.username, args.app_password, args.encrypt_key,
            )
            logger.info("Processed %d email(s)", count)

    elif args.daemon:
        logger.info("Starting daemon mode (interval: %ds)", args.interval)
        while True:
            try:
                with app.app_context():
                    count = fetch_and_process(
                        args.imap_host, args.imap_port,
                        args.username, args.app_password, args.encrypt_key,
                    )
                    if count > 0:
                        logger.info("Processed %d email(s)", count)
            except Exception as e:
                logger.error("Fetch cycle failed: %s", e)

            time.sleep(args.interval)


if __name__ == "__main__":
    main()
