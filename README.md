# hashing-playground

A teaching CLI for the building blocks of password storage and integrity checks:
cryptographic digests, HMAC, PBKDF2 password hashing, verification and
constant-time comparison. Every operation uses the Python standard library.

> MD5 is included **only** to show why it must not be used for security. The tool
> labels it as insecure.

## Features

- `sha256`, `sha512`: digests of text or files.
- `hmac`: keyed message authentication.
- `pbkdf2`: derive and verify password hashes with a salt and iteration count.
- `compare`: constant-time comparison (`hmac.compare_digest`).
- Known-answer tests for the digest and PBKDF2 implementations.

## Installation

```bash
git clone https://github.com/victor-harden/hashing-playground.git
cd hashing-playground
```

## Usage

```bash
python3 playground.py sha256 --text "hello"
python3 playground.py sha256 --file README.md
python3 playground.py hmac --key secret --text "message"
python3 playground.py pbkdf2 --password "correct horse" --salt deadbeef --iterations 100000
python3 playground.py verify-pbkdf2 --password "correct horse" --salt deadbeef --iterations 100000 --hash <hex>
python3 playground.py compare --a abc --b abc
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
