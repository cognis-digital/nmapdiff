"""NMAPDIFF MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from nmapdiff.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-nmapdiff[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-nmapdiff[mcp]'")
        return 1
    app = FastMCP("nmapdiff")

    @app.tool()
    def nmapdiff_scan(target: str) -> str:
        """Diff two scans to surface new hosts/ports/services. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
