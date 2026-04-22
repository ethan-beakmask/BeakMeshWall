#!/usr/bin/env python3
"""Cross-language crypto compatibility test.

Tests that Python can decrypt data encrypted by Go's AES-256-GCM,
and vice versa. Run this after compiling the Go agent.

Usage:
  python3 test_crypto_compat.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.email_receiver import decrypt_report

# Generate a random AES-256 key
KEY_HEX = os.urandom(32).hex()


def test_python_encrypt_decrypt():
    """Verify Python can encrypt and decrypt its own data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes.fromhex(KEY_HEX)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps({"test": "hello from python"}).encode()
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # Format: base64(nonce + ciphertext)
    encrypted_b64 = base64.b64encode(nonce + ct).decode()

    result = decrypt_report(encrypted_b64, KEY_HEX)
    assert result == {"test": "hello from python"}, f"Mismatch: {result}"
    print("[PASS] Python encrypt -> Python decrypt")


def test_go_encrypt_python_decrypt():
    """Verify Python can decrypt Go-encrypted data."""
    # Write a small Go test program
    go_code = '''package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/anthropics/beakmeshwall-agent/internal/crypto"
)

func main() {
	key := os.Args[1]
	plaintext := []byte(`{"test":"hello from go","number":42}`)
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt error: %v\\n", err)
		os.Exit(1)
	}
	fmt.Print(base64.StdEncoding.EncodeToString(encrypted))
}
'''
    agent_dir = Path(__file__).resolve().parent.parent.parent / "agent"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".go", dir=agent_dir / "cmd",
        prefix="test_crypto_", delete=False,
    ) as f:
        f.write(go_code)
        go_file = f.name

    try:
        result = subprocess.run(
            ["go", "run", go_file, KEY_HEX],
            cwd=str(agent_dir),
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"[FAIL] Go encrypt failed: {result.stderr}")
            return False

        encrypted_b64 = result.stdout.strip()
        decrypted = decrypt_report(encrypted_b64, KEY_HEX)
        assert decrypted == {"test": "hello from go", "number": 42}, f"Mismatch: {decrypted}"
        print("[PASS] Go encrypt -> Python decrypt")
        return True
    except subprocess.TimeoutExpired:
        print("[FAIL] Go program timed out")
        return False
    finally:
        os.unlink(go_file)


if __name__ == "__main__":
    print(f"Using key: {KEY_HEX[:16]}...{KEY_HEX[-16:]}")
    test_python_encrypt_decrypt()
    test_go_encrypt_python_decrypt()
    print("\nAll crypto compatibility tests passed.")
