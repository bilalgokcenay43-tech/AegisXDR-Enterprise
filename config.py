"""
Centralized Configuration Module for AegisXDR-Enterprise.
Manages AES-256 encryption keys, database connections, SIEM engine thresholds, and SOAR response settings.
"""

import os
import base64
from typing import List
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "AegisXDR-Enterprise"
    VERSION: str = "2.0.0"
    DEBUG: bool = os.getenv("AEGIS_DEBUG", "True").lower() == "true"
    
    # Server Host & Port
    HOST: str = os.getenv("AEGIS_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("AEGIS_PORT", "8000"))
    
    # Database Settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegis_xdr.db")
    
    # Cryptography - AES-256 GCM Key (32 bytes base64 encoded)
    AES_SECRET_KEY_B64: str = os.getenv(
        "AEGIS_AES_KEY",
        base64.b64encode(b"AegisXDR_Secure_AES256_Key_32Bytes!").decode("utf-8")
    )
    
    # SIGMA Rules Path
    SIGMA_RULES_DIR: str = os.getenv(
        "SIGMA_RULES_DIR",
        os.path.join(os.path.dirname(__file__), "server", "detectors", "rules")
    )
    
    # Suspicious Command Line Flags
    SUSPICIOUS_CLI_FLAGS: List[str] = [
        "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
        "-nop", "-noprofile", "bypass", "-noni", "downloadstring", "invoke-expression",
        "iex", "cmd /c", "certutil -urlcache", "vssadmin delete shadows", "rundll32.exe"
    ]
    
    # High-Risk Parent-Child Process Mappings
    SUSPICIOUS_PARENT_CHILD: List[dict] = [
        {"parent": "winword.exe", "child": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe"]},
        {"parent": "excel.exe", "child": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]},
        {"parent": "powerpnt.exe", "child": ["powershell.exe", "cmd.exe"]},
        {"parent": "outlook.exe", "child": ["powershell.exe", "cmd.exe"]},
        {"parent": "mshta.exe", "child": ["powershell.exe", "cmd.exe"]},
        {"parent": "wscript.exe", "child": ["powershell.exe", "cmd.exe"]},
        {"parent": "services.exe", "child": ["powershell.exe", "cmd.exe"]}
    ]
    
    # SOAR Engine Controls
    AUTO_ISOLATE_ENABLED: bool = os.getenv("AEGIS_AUTO_ISOLATE", "True").lower() == "true"
    AUTO_TERMINATE_SUSPICIOUS_CHILDREN: bool = os.getenv("AEGIS_AUTO_TERMINATE", "True").lower() == "true"

    @property
    def raw_aes_key(self) -> bytes:
        """Decodes the base64 encoded secret key and ensures 32-byte key for AES-256."""
        import hashlib
        key = base64.b64decode(self.AES_SECRET_KEY_B64)
        if len(key) != 32:
            return hashlib.sha256(key).digest()
        return key

settings = Settings()
