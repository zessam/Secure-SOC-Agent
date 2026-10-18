"""Mock identity writes (write-only): password resets, session revocation, account and group changes."""
from __future__ import annotations

from .common.write_server import build_write_server, serve_write

ACTIONS = {
    "reset_password": "Force a password reset for an account",
    "revoke_sessions": "Revoke all sign-in sessions and refresh tokens of an account",
    "disable_user": "Disable an account",
    "remove_group_member": "Remove a member from a group (target 'user from Group')",
    "remove_inbox_rule": "Delete malicious mailbox inbox rules of a user",
    "disable_legacy_auth": "Block legacy authentication (IMAP/POP/SMTP basic auth)",
    "clear_ad_description": "Clear an AD description attribute that holds a secret",
}


def build_server():
    return build_write_server("ad-write-mcp", "Identity", ACTIONS)


if __name__ == "__main__":
    serve_write(build_server)
