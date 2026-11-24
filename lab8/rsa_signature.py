"""Электронная подпись RSA для файлов с SHA-256."""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == q:
            return True
        if n % q == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(40):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 64:
        raise ValueError("Для генерации задайте не менее 64 бит на простой множитель.")
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def generate_keys(private: Path, public: Path, bits: int = 512) -> None:
    e = 65537
    while True:
        p, q = generate_prime(bits), generate_prime(bits)
        if p != q and __import__("math").gcd(e, (p - 1) * (q - 1)) == 1:
            break
    n = p * q; d = pow(e, -1, (p - 1) * (q - 1))
    private.write_text(json.dumps({"n": n, "d": d}, indent=2) + "\n", encoding="utf-8")
    public.write_text(json.dumps({"n": n, "e": e}, indent=2) + "\n", encoding="utf-8")


def sign_file(file: Path, key_file: Path, signature_file: Path) -> None:
    key = json.loads(key_file.read_text(encoding="utf-8")); n, d = key["n"], key["d"]
    digest = hashlib.sha256(file.read_bytes()).digest()
    h = int.from_bytes(digest, "big")
    if h >= n:
        raise ValueError("Модуль RSA слишком мал для SHA-256.")
    signature_file.write_text(json.dumps({"algorithm": "RSA textbook (учебная)", "hash": "SHA-256",
                                          "sha256": digest.hex(), "signature": pow(h, d, n)}, indent=2) + "\n", encoding="utf-8")


def verify_file(file: Path, key_file: Path, signature_file: Path) -> bool:
    key = json.loads(key_file.read_text(encoding="utf-8")); sig = json.loads(signature_file.read_text(encoding="utf-8"))
    n, e, value = key["n"], key["e"], sig["signature"]
    if not 0 <= value < n:
        return False
    digest = hashlib.sha256(file.read_bytes()).digest()
    return pow(value, e, n) == int.from_bytes(digest, "big")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__); sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--private", type=Path, default=Path("private.json")); k.add_argument("--public", type=Path, default=Path("public.json")); k.add_argument("--bits", type=int, default=512)
    s = sub.add_parser("sign"); s.add_argument("file", type=Path); s.add_argument("--key", type=Path, default=Path("private.json")); s.add_argument("--out", type=Path)
    v = sub.add_parser("verify"); v.add_argument("file", type=Path); v.add_argument("signature", type=Path); v.add_argument("--key", type=Path, default=Path("public.json"))
    a = ap.parse_args()
    if a.cmd == "keygen":
        generate_keys(a.private, a.public, a.bits); print("Пара ключей создана.")
    elif a.cmd == "sign":
        out = a.out or Path(str(a.file) + ".sig"); sign_file(a.file, a.key, out); print(f"Подпись записана: {out}")
    else:
        print("Подпись верна." if verify_file(a.file, a.key, a.signature) else "Подпись НЕВЕРНА.")


if __name__ == "__main__":
    main()
