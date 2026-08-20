#!/usr/bin/env python3
"""
aes_encryptor.py - AES-256-CBC + PBKDF2-HMAC-SHA256 payload encryptor
for the NetLoader_AES reflective loader.

Produces the exact blob format expected by NetLoader_AES.cs:

    b"AES1"  (4 bytes magic)
    || salt  (16 bytes, random, per-encryption)
    || iv    (16 bytes, random, per-encryption)
    || AES-256-CBC(PKCS7) ciphertext

Parameters mirror the loader exactly:
    KDF       : PBKDF2-HMAC-SHA256
    iterations: 120000
    key size  : 32 bytes (AES-256)
    password  : UTF-8 encoded
    padding   : PKCS7

Usage:
    Encrypt:
      python3 aes_encryptor.py --key 's3cr3t' --in payload.exe --out payload.exe.aes
      python3 aes_encryptor.py --key-env PAYLOAD_KEY --in payload.exe
      python3 aes_encryptor.py --key-stdin --in payload.exe --out staged.bin
      python3 aes_encryptor.py --key 's3cr3t' --in payload.exe --b64
    Decrypt / verify:
      python3 aes_encryptor.py --decrypt --key 's3cr3t' --in payload.exe.aes --out restored.exe

Dependencies: pycryptodome (preferred) or the `cryptography` package.
"""

import argparse
import base64
import getpass
import hashlib
import os
import sys

MAGIC = b"AES1"
ITERATIONS = 120000
SALT_LEN = 16
IV_LEN = 16
KEY_LEN = 32
MIN_KEY_LEN = 12

# ---------------- AES backend (pycryptodome preferred) ----------------

def _aes_encrypt_cbc(key, iv, plaintext):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        padder = padding.PKCS7(128).padder()
        data = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(data) + enc.finalize()


def _aes_decrypt_cbc(key, iv, ciphertext):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        data = dec.update(ciphertext) + dec.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()


# ---------------- core ops ----------------

def derive_key(passphrase, salt):
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, ITERATIONS, KEY_LEN)


def encrypt_blob(plaintext, passphrase):
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(passphrase, salt)
    try:
        cipher = _aes_encrypt_cbc(key, iv, plaintext)
    finally:
        key = None
    return MAGIC + salt + iv + cipher


def decrypt_blob(blob, passphrase):
    if len(blob) < 4 + SALT_LEN + IV_LEN + 16:
        raise ValueError("blob too small; is this an AES1 payload?")
    if blob[:4] != MAGIC:
        raise ValueError("bad magic: not an AES-256 NetLoader payload")

    salt = blob[4:4 + SALT_LEN]
    iv = blob[4 + SALT_LEN:4 + SALT_LEN + IV_LEN]
    cipher = blob[4 + SALT_LEN + IV_LEN:]

    key = derive_key(passphrase, salt)
    try:
        return _aes_decrypt_cbc(key, iv, cipher)
    finally:
        key = None


# ---------------- CLI ----------------

def resolve_key(args):
    if args.key:
        return args.key
    if args.key_env:
        value = os.environ.get(args.key_env)
        if not value:
            sys.exit(f"[!] Environment variable {args.key_env} is not set")
        return value
    if args.key_stdin:
        try:
            return getpass.getpass("Passphrase: ")
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
    sys.exit("[!] Provide a passphrase via --key, --key-env, or --key-stdin")


def main():
    p = argparse.ArgumentParser(
        description="AES-256-CBC + PBKDF2-SHA256 encryptor for NetLoader_AES",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Output is written to <input>.aes unless --out/--b64 is used.",
    )
    p.add_argument("--in", dest="in_file", required=True, help="input file (payload, or .aes blob with --decrypt)")
    p.add_argument("--out", dest="out_file", help="output file (default: <input>.aes / <input>.dec)")
    p.add_argument("--decrypt", action="store_true", help="decrypt/verify mode")
    p.add_argument("--key", help="passphrase (visible in process list; prefer --key-env/--key-stdin)")
    p.add_argument("--key-env", metavar="VAR", help="read passphrase from environment variable")
    p.add_argument("--key-stdin", action="store_true", help="prompt for passphrase on stdin")
    p.add_argument("--b64", action="store_true", help="print base64 of the result instead of writing a file")
    args = p.parse_args()

    key = resolve_key(args)
    if len(key) < MIN_KEY_LEN:
        print(f"[!] Warning: passphrase is only {len(key)} chars; use {MIN_KEY_LEN}+ for operational payloads")

    with open(args.in_file, "rb") as f:
        data = f.read()

    if args.decrypt:
        plain = decrypt_blob(data, key)
        result_name = "plaintext"
        out_bytes = plain
    else:
        blob = encrypt_blob(data, key)
        result_name = "AES1 blob"
        out_bytes = blob

    if args.b64:
        sys.stdout.buffer.write(base64.b64encode(out_bytes) + b"\n")
        return

    out_file = args.out_file or (args.in_file + (".dec" if args.decrypt else ".aes"))
    with open(out_file, "wb") as f:
        f.write(out_bytes)
    print(f"[+] {result_name}: {len(data)} -> {len(out_bytes)} bytes -> {out_file}")


if __name__ == "__main__":
    main()
