"""Mock SOAR playbooks (write-only): network/email blocks, mail purge, user contact, escalation, case updates."""
from __future__ import annotations

from .common.write_server import build_write_server, serve_write

ACTIONS = {
    "block_ip": "Block an IP on the perimeter firewall",
    "block_domain": "Block a domain on the web proxy and DNS",
    "block_sender_domain": "Block a sender domain on the email gateway",
    "purge_email": "Delete a phishing email from all mailboxes",
    "contact_user": "Send the user a 'was this you?' verification",
    "escalate": "Page the Incident Response team",
    "close_case": "Close the SOAR case",
    "propose_detection_tuning": "Open a detection-engineering ticket to tune a rule",
}


def build_server():
    return build_write_server("soar-write-mcp", "SOAR", ACTIONS)


if __name__ == "__main__":
    serve_write(build_server)
