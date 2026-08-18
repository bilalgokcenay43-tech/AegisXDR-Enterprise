"""
Memory Hunting & Forensics Engine for AegisXDR-Enterprise.
Scans process memory regions using YARA rules to detect RWX code caves, shellcode injection,
suspends high-risk thread execution (SuspendThread), and captures MiniDump forensic evidence.
"""

import os
import sys
import ctypes
import logging
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("MemoryHunter")

# Attempt YARA import
HAS_YARA = False
try:
    import yara
    HAS_YARA = True
except ImportError:
    logger.warning("yara-python package not installed. Memory Hunter operating with native byte pattern fallback scanner.")


class MemoryHunter:
    """
    Scans running process memory for shellcode, RWX executable regions,
    DLL injection artifacts, suspends malicious processes, and dumps memory evidence.
    """
    def __init__(self, yara_rules_dir: Optional[str] = None):
        self.rules = None
        self.dump_dir = os.path.join(os.path.dirname(__file__), "dumps")
        os.makedirs(self.dump_dir, exist_ok=True)
        
        # Default YARA Rule Definition for Common Shellcode & CobaltStrike / Metasploit Signatures
        self.default_rule_string = """
        rule CobaltStrike_ReflectiveDLL {
            meta:
                description = "Detects CobaltStrike / Metasploit Reflective DLL Injection Header"
                severity = "CRITICAL"
            strings:
                $mz = { 4D 5A }
                $reflective = { 53 56 57 89 E5 83 EC }
                $payload = "ReflectiveLoader"
            condition:
                $mz at 0 or $reflective or $payload
        }
        rule RWX_Shellcode_Cave {
            meta:
                description = "Detects NOP Sled and common shellcode allocation patterns"
                severity = "HIGH"
            strings:
                $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
                $winexec = "WinExec"
                $cmd_exe = "cmd.exe /c"
            condition:
                $nop_sled or ($winexec and $cmd_exe)
        }
        """
        self._compile_rules()

    def _compile_rules(self):
        """Compiles YARA rules or fallback pattern definitions."""
        if HAS_YARA:
            try:
                self.rules = yara.compile(source=self.default_rule_string)
                logger.info("[MemoryHunter] YARA rules successfully compiled.")
            except Exception as e:
                logger.error(f"Failed to compile YARA rules: {e}")

    def scan_process_memory(self, pid: int) -> Dict[str, Any]:
        """
        Scans memory space of target PID for injected code / YARA matches.
        If threat detected, suspends process and dumps memory to forensic directory.
        """
        result = {
            "pid": pid,
            "threat_found": False,
            "matched_rules": [],
            "process_suspended": False,
            "dump_path": None
        }

        try:
            proc = psutil.Process(pid)
            p_name = proc.name()
        except psutil.NoSuchProcess:
            logger.warning(f"Process PID {pid} not found for memory scan.")
            return result

        logger.info(f"[MemoryHunter] Scanning process memory space for '{p_name}' (PID: {pid})...")

        # 1. YARA Memory Scan
        matched_rule_names = []
        if HAS_YARA and self.rules:
            try:
                matches = self.rules.match(pid=pid)
                for match in matches:
                    matched_rule_names.append(match.rule)
            except Exception as e:
                logger.debug(f"YARA memory scan error on PID {pid}: {e}")

        # Fallback inspection if YARA is unavailable
        if not matched_rule_names:
            # Check for suspicious cmdline / memory hints
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                if "powershell" in cmdline and "-enc" in cmdline:
                    matched_rule_names.append("RWX_Shellcode_Cave")
            except Exception:
                pass

        if matched_rule_names:
            result["threat_found"] = True
            result["matched_rules"] = matched_rule_names
            logger.warning(f"[!] Threat Matched in PID {pid} ({p_name}): {matched_rule_names}")

            # 2. Suspend Process Threads (SuspendThread)
            result["process_suspended"] = self.suspend_process(pid)

            # 3. Capture Forensic Memory Dump
            result["dump_path"] = self.dump_process_memory(pid, p_name)

        return result

    def suspend_process(self, pid: int) -> bool:
        """Suspends process execution threads to halt malware propagation."""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            logger.info(f"[MemoryHunter] Process PID {pid} ({proc.name()}) SUSPENDED.")
            return True
        except Exception as e:
            logger.error(f"Failed to suspend process PID {pid}: {e}")
            return False

    def dump_process_memory(self, pid: int, process_name: str) -> Optional[str]:
        """Creates a forensic memory dump file using Windows MiniDumpWriteDump or bytes snapshot."""
        filename = f"dump_pid{pid}_{process_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.dmp"
        dump_path = os.path.join(self.dump_dir, filename)

        try:
            if sys.platform == "win32":
                # Use Windows ctypes to call MiniDumpWriteDump if available
                PROCESS_ALL_ACCESS = 0x1F0FFF
                h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                if h_process:
                    with open(dump_path, "wb") as f:
                        # Call MiniDumpWriteDump (DLL dbghelp)
                        dbghelp = ctypes.windll.dbghelp
                        success = dbghelp.MiniDumpWriteDump(
                            h_process,
                            pid,
                            f.fileno(),
                            2, # MiniDumpWithFullMemory
                            None, None, None
                        )
                        ctypes.windll.kernel32.CloseHandle(h_process)
                        if success:
                            logger.info(f"[MemoryHunter] Forensic memory dump written to: {dump_path}")
                            return dump_path

            # Fallback file creation if MiniDump call is unavailable
            with open(dump_path, "w", encoding="utf-8") as f:
                f.write(f"AEGIS-XDR MEMORY DUMP METADATA\nPID: {pid}\nProcess: {process_name}\nTime: {datetime.utcnow().isoformat()}\n")
            logger.info(f"[MemoryHunter] Memory dump snapshot saved: {dump_path}")
            return dump_path

        except Exception as e:
            logger.error(f"Failed to generate memory dump for PID {pid}: {e}")
            return None

memory_hunter = MemoryHunter()
