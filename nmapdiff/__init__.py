"""NMAPDIFF — diff two nmap scans to surface new hosts/ports/services.

Defensive / authorized-testing tool: analysis and change-detection only.
No scanning, no network access, no attack capability.
"""

from nmapdiff.core import (
    Diff,
    HostDiff,
    PortChange,
    ScanReport,
    diff_scans,
    parse_scan,
    parse_scan_file,
)

TOOL_NAME = "nmapdiff"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "ScanReport",
    "PortChange",
    "HostDiff",
    "Diff",
    "parse_scan",
    "parse_scan_file",
    "diff_scans",
]
