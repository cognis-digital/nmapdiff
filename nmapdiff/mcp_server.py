"""NMAPDIFF MCP server — exposes diff_scans() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from nmapdiff.core import diff_scans, parse_scan_file


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-nmapdiff[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except Exception:
        print("Install the MCP extra: pip install 'cognis-nmapdiff[mcp]'")
        return 1
    app = FastMCP("nmapdiff")

    @app.tool()
    def nmapdiff_diff(baseline: str, current: str) -> str:
        """Diff two nmap XML scan files and return JSON findings.

        Args:
            baseline: path to the baseline nmap XML (-oX) file.
            current:  path to the current nmap XML (-oX) file.
        """
        try:
            b = parse_scan_file(baseline)
            c = parse_scan_file(current)
        except (OSError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(diff_scans(b, c).to_dict(), indent=2, sort_keys=True)

    app.run()
    return 0
