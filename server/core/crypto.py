"""
AES-256 GCM Encryption & Decryption Utility for AegisXDR-Enterprise.
Ensures secure zero-trust communication between endpoint collector agents and the ingestion core.
"""

import os
import json
import base64
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import settings

class AES256Engine:
    def __init__(self, secret_key: bytes = None):
        self.key = secret_key or settings.raw_aes_key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, payload: Dict[str, Any]) -> str:
        """
        Encrypts a dictionary payload into a Base64 string containing:
        Nonce (12 bytes) + Ciphertext + Tag (16 bytes)
        """
        data = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode("utf-8")

    def decrypt(self, encrypted_b64: str) -> Dict[str, Any]:
        """
        Decrypts a Base64 string containing Nonce + Ciphertext back into a Python dictionary.
        """
        try:
            combined = base64.b64decode(encrypted_b64)
            if len(combined) < 28: # 12 nonce + 16 auth tag minimum
                raise ValueError("Payload size too short for AES-GCM tag and nonce")
            
            nonce = combined[:12]
            ciphertext = combined[12:]
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"AES-256 Decryption Failed: {str(e)}")

# Global Crypto Engine Singleton
crypto_engine = AES256Engine()
