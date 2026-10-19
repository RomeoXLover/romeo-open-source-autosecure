#!/usr/bin/env python3
"""Test the extracted mail handler's OTP detection and mode selection."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from extracted.mail.handler import detect_otp, get_mail_mode, load_token_config


def main():
    tests = [
        ("Microsoft code", "Your code is: ABC123-DEF456 please", "alphanumeric"),
        ("Microsoft verify", "code: 482910", "numeric"),
        ("Token", "guid: 4c27fcab-7ffb-41c0-86f2-0f97f84aed33 here", "guid"),
        ("No match", "Invoice for stuff", None),
        ("No keywords", "ABC123 here but no keyword", None),
    ]
    print("[test] otp detection:")
    all_passed = True
    for subj, body, expected in tests:
        hit = detect_otp(subj, body)
        got = hit["type"] if hit else None
        ok = got == expected
        if not ok:
            all_passed = False
        got_str = got if got is not None else "None"
        exp_str = expected if expected is not None else "None"
        print(f"  {'ok  ' if ok else 'FAIL'} {subj:20s} expected={exp_str:15s} got={got_str}")

    cfg = load_token_config()
    print(f"\n[test] mode: {get_mail_mode(cfg)}")
    print(f"[test] bot_token: {'present' if cfg.get('bot_token') else 'MISSING'}")
    print(f"[test] imap: {cfg.get('imap', {}).get('host', 'none')}")
    print(f"[test] cloudflare: port={cfg.get('cloudflare', {}).get('port', 'none')}")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
