"""Helpers shared by cloud API tests."""
import base64
import json


def valid_blob(payload: bytes = b"test-vault") -> str:
    """Build a structurally valid encrypted-vault envelope."""
    payload = payload.ljust(256, b"\x00")
    return json.dumps(
        {
            "salt": base64.b64encode(b"\x00" * 16).decode("ascii"),
            "nonce": base64.b64encode(b"\x00" * 12).decode("ascii"),
            "ciphertext": base64.b64encode(payload + b"\x00" * 16).decode("ascii"),
            "version": "1",
        }
    )
