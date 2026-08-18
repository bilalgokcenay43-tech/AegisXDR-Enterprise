"""
Endpoint Collector Cryptographic Helper module for AegisXDR-Enterprise.
Handles client-side AES-256 payload encryption before transmission to SIEM server.
"""

import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AgentCrypto:
    def __init__(self, raw_key: bytes):
        import hashlib
        if len(raw_key) != 32:
            raw_key = hashlib.sha256(raw_key).digest()
        self.aesgcm = AESGCM(raw_key)

    def encrypt_telemetry(self, payload: dict) -> str:
        """Encrypts dictionary payload using AES-256 GCM."""
        data = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")
