#!/usr/bin/python3
"""Authenticate legacy and named Hysteria users without logging credentials."""
import hashlib
import hmac
import json
import sys

def main():
    if len(sys.argv) != 4:
        return 1
    with open('/etc/hysteria2-nider/auth-users.json', encoding='utf-8') as stream:
        users = json.load(stream)
    supplied = hashlib.sha256(sys.argv[2].encode()).hexdigest()
    for username, expected in users.items():
        if hmac.compare_digest(supplied, expected):
            print(username)
            return 0
    return 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError):
        sys.exit(1)
