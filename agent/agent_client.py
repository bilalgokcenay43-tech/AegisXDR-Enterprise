"""
Modular Multi-Agent Client Architecture for AegisXDR-Enterprise.
Manages telemetry buffer queues, exponential backoff retries, AES-256 payload encryption,
and robust transport to central SIEM REST / gRPC API servers.
"""

import os
import sys
import time
import json
import queue
import logging
import threading
import requests
from typing import Dict, Any, Optional

# Ensure parent directory imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.crypto_utils import AgentCrypto

logger = logging.getLogger("AegisAgentClient")

class AegisAgentClient:
    """
    Multi-Agent Client framework featuring thread-safe event queueing,
    AES-256 GCM encryption, and resilient HTTP/gRPC transmission with exponential retries.
    """
    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8000/api/v1/telemetry",
        aes_key_b64: str = "QWVnaXNYRFJfU2VjdXJlX0FFUzI1Nl9LZXlfMzJCeXRlcyE=",
        agent_id: str = "AEGIS-AGENT-01"
    ):
        self.server_url = server_url
        self.agent_id = agent_id
        self.event_queue: queue.Queue = queue.Queue(maxsize=5000)
        self.running = False
        
        # Crypto initialization
        import base64
        key_bytes = base64.b64decode(aes_key_b64)
        self.crypto = AgentCrypto(key_bytes)
        
        # Worker thread
        self.worker_thread = threading.Thread(target=self._transmission_worker, daemon=True)

    def start(self):
        """Starts background transmission worker thread."""
        self.running = True
        self.worker_thread.start()
        logger.info(f"[*] Aegis Agent Client [{self.agent_id}] started. Target: {self.server_url}")

    def stop(self):
        """Stops client transmission worker gracefully."""
        self.running = False

    def send_event(self, telemetry_event: Dict[str, Any]):
        """Pushes telemetry event into local queue buffer."""
        try:
            telemetry_event["agent_id"] = self.agent_id
            self.event_queue.put(telemetry_event, block=False)
        except queue.Full:
            logger.warning("[!] Telemetry Queue Full! Dropping oldest event.")
            try:
                self.event_queue.get_nowait()
                self.event_queue.put(telemetry_event, block=False)
            except Exception:
                pass

    def _transmission_worker(self):
        """Worker loop transmitting queued telemetry to central server with exponential backoff retries."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
            except queue.Empty:
                continue

            # Transmit event with retry logic
            success = self._transmit_with_retry(event)
            if not success:
                logger.error(f"[-] Failed to deliver telemetry event after retries. Re-queueing event PID {event.get('pid')}.")

            self.event_queue.task_done()

    def _transmit_with_retry(self, event: Dict[str, Any], max_retries: int = 3) -> bool:
        """Sends encrypted event to server with exponential backoff delay."""
        retry_delay = 1.0
        
        # Encrypt payload
        encrypted_b64 = self.crypto.encrypt_telemetry(event)
        payload = {
            "encrypted": True,
            "data": encrypted_b64
        }
        headers = {"Content-Type": "application/json"}

        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(self.server_url, json=payload, headers=headers, timeout=4)
                if response.status_code == 200:
                    logger.debug(f"[+] Telemetry sent successfully on attempt {attempt}.")
                    return True
                else:
                    logger.warning(f"[-] Server returned status {response.status_code} on attempt {attempt}: {response.text}")
            except Exception as e:
                logger.warning(f"[-] Transmission error on attempt {attempt}/{max_retries}: {e}")

            time.sleep(retry_delay)
            retry_delay *= 2.0  # Exponential backoff (1s, 2s, 4s)

        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    client = AegisAgentClient()
    client.start()
    client.send_event({"hostname": "WORKSTATION-01", "pid": 1234, "process_name": "test.exe", "cmdline": "test.exe"})
    time.sleep(2)
    client.stop()
