#!/usr/bin/env python3
"""One-time setup: writes extracted/token.json from a template.

Run this once to create your private config:
    python extracted/mail/setup.py

Then edit extracted/token.json to fill in your real credentials.
No credentials are committed to git — token.json is gitignored.
"""
import os
import json

TOKEN_TEMPLATE = {
    "bot_token": "YOUR_DISCORD_BOT_TOKEN_HERE",
    "mail_mode": "smtp",
    "imap": {
        "host": "mail.yourdomain.com",
        "port": 993,
        "user": "romeo@yourdomain.com",
        "pass": "your-app-password"
    },
    "cloudflare": {
        "port": 8765,
        "secret": "some-secret-key-for-auth"
    },
    "smtp": {
        "host": "mail.yourdomain.com",
        "port": 587,
        "user": "romeo@yourdomain.com",
        "pass": "your-app-password"
    }
}


def main():
    extracted = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(extracted, "token.json")

    if os.path.exists(path):
        print(f"[ok] {path} already exists — not overwriting")
        return

    # Make sure .gitignore ignores token.json
    gitignore = os.path.join(os.path.dirname(os.path.dirname(extracted)), ".gitignore")
    if os.path.exists(gitignore):
        with open(gitignore, "r") as f:
            lines = f.read()
        if "extracted/token.json" not in lines:
            with open(gitignore, "a") as f:
                f.write("\nextracted/token.json\n")

    with open(path, "w") as f:
        json.dump(TOKEN_TEMPLATE, f, indent=2)

    print(f"[+] wrote {path}")
    print("[i] edit it to add your real credentials, then restart romeo-bot")
    print("[i] mail_mode = 'smtp' for local IMAP polling")
    print("[i] mail_mode = 'cloudflare' for worker webhook (set cloudflare.port)")


if __name__ == "__main__":
    main()
