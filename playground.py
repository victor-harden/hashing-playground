#!/usr/bin/env python3
"""Hashing, HMAC and PBKDF2 playground (standard library only)."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
from pathlib import Path

DIGESTS = {"sha256": hashlib.sha256, "sha512": hashlib.sha512, "md5": hashlib.md5}


def digest(data: bytes, algorithm: str = "sha256") -> str:
    try:
        constructor = DIGESTS[algorithm]
    except KeyError as exc:
        raise ValueError(f"unsupported algorithm: {algorithm}") from exc
    return constructor(data).hexdigest()


def hmac_hex(key: bytes, message: bytes, algorithm: str = "sha256") -> str:
    return hmac.new(key, message, DIGESTS[algorithm]).hexdigest()


def pbkdf2(password: str, salt: bytes, iterations: int = 100_000,
           algorithm: str = "sha256") -> str:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    return hashlib.pbkdf2_hmac(algorithm, password.encode("utf-8"), salt, iterations).hex()


def verify_pbkdf2(password: str, salt: bytes, iterations: int, expected_hex: str,
                  algorithm: str = "sha256") -> bool:
    candidate = pbkdf2(password, salt, iterations, algorithm)
    return hmac.compare_digest(candidate, expected_hex)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def read_bytes(text: str | None, file: str | None) -> bytes:
    if text is not None:
        return text.encode("utf-8")
    if file is not None:
        return Path(file).read_bytes()
    raise ValueError("provide --text or --file")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Hashing playground")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("sha256", "sha512", "md5"):
        p = sub.add_parser(name, help=f"{name} digest")
        p.add_argument("--text")
        p.add_argument("--file")

    p = sub.add_parser("hmac", help="HMAC of a message")
    p.add_argument("--key", required=True)
    p.add_argument("--text")
    p.add_argument("--file")
    p.add_argument("--algorithm", default="sha256", choices=sorted(DIGESTS))

    p = sub.add_parser("pbkdf2", help="derive a PBKDF2 hash")
    p.add_argument("--password", required=True)
    p.add_argument("--salt", help="hex salt (random if omitted)")
    p.add_argument("--iterations", type=int, default=100_000)

    p = sub.add_parser("verify-pbkdf2", help="verify a PBKDF2 hash")
    p.add_argument("--password", required=True)
    p.add_argument("--salt", required=True)
    p.add_argument("--iterations", type=int, required=True)
    p.add_argument("--hash", required=True)

    p = sub.add_parser("compare", help="constant-time comparison")
    p.add_argument("--a", required=True)
    p.add_argument("--b", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command in DIGESTS:
            data = read_bytes(args.text, args.file)
            print(digest(data, args.command))
            if args.command == "md5":
                print("warning: MD5 is not collision resistant; do not use it for security",
                      file=sys.stderr)
        elif args.command == "hmac":
            data = read_bytes(args.text, args.file)
            print(hmac_hex(args.key.encode("utf-8"), data, args.algorithm))
        elif args.command == "pbkdf2":
            salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
            print(f"salt: {salt.hex()}")
            print(f"iterations: {args.iterations}")
            print(pbkdf2(args.password, salt, args.iterations))
        elif args.command == "verify-pbkdf2":
            ok = verify_pbkdf2(args.password, bytes.fromhex(args.salt),
                               args.iterations, args.hash)
            print("match" if ok else "no match")
            return 0 if ok else 1
        else:
            same = constant_time_equal(args.a, args.b)
            print("equal" if same else "different")
            return 0 if same else 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
