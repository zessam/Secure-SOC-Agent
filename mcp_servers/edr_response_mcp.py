"""Mock EDR response (write-only): isolate hosts, kill processes, quarantine files, scans, hash blocks."""
from __future__ import annotations

from .common.write_server import build_write_server, serve_write

ACTIONS = {
    "isolate_host": "Network-isolate a host (EDR keeps its own connection)",
    "kill_process": "Kill a process on a host (target 'HOST:pid')",
    "quarantine_file": "Quarantine a file (target 'HOST:path')",
    "run_av_scan": "Run a full antivirus scan on a host",
    "block_hash": "Add a file hash to the EDR block list",
}


def build_server():
    return build_write_server("edr-response-mcp", "EDR", ACTIONS)


if __name__ == "__main__":
    serve_write(build_server)
