"""Шифр Вернама для произвольных файлов с ключевым потоком из Диффи—Хеллмана."""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path

MAGIC = b"VERNAM1\0"


def probable_prime(n: int) -> bool:
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
    for _ in range(32):
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


def prime(bits: int = 256) -> int:
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if probable_prime(n):
            return n


def dh_key(p: int, g: int, x_a: int, x_b: int) -> int:
    if not probable_prime(p) or not 1 < g < p:
        raise ValueError("p должно быть простым, а g — лежать между 1 и p.")
    if not (1 <= x_a < p - 1 and 1 <= x_b < p - 1):
        raise ValueError("Секретные показатели должны лежать в диапазоне [1, p−2].")
    a, b = pow(g, x_a, p), pow(g, x_b, p)
    ka, kb = pow(b, x_a, p), pow(a, x_b, p)
    if ka != kb:
        raise RuntimeError("Абоненты получили разные секреты.")
    return ka


def _stream(shared: int, salt: bytes, size: int) -> bytes:
    seed = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(b"lab7-vernam" + salt + seed + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(output[:size])


def transform(source: Path, target: Path, shared: int, salt: bytes | None = None) -> bytes:
    data = source.read_bytes()
    if salt is None:
        salt = secrets.token_bytes(16)
        stream = _stream(shared, salt, len(data))
        target.write_bytes(MAGIC + salt + len(data).to_bytes(8, "big") + bytes(a ^ b for a, b in zip(data, stream)))
    else:
        raw = data
        if not raw.startswith(MAGIC) or len(raw) < len(MAGIC) + 24:
            raise ValueError("Неверный формат шифротекста.")
        salt = raw[len(MAGIC):len(MAGIC) + 16]
        size = int.from_bytes(raw[len(MAGIC) + 16:len(MAGIC) + 24], "big")
        cipher = raw[len(MAGIC) + 24:]
        if len(cipher) != size:
            raise ValueError("Размер данных не соответствует заголовку.")
        stream = _stream(shared, salt, size)
        target.write_bytes(bytes(a ^ b for a, b in zip(cipher, stream)))
    return salt


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__); sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt"); e.add_argument("file", type=Path); e.add_argument("--out", type=Path)
    e.add_argument("--p", type=int); e.add_argument("--g", type=int); e.add_argument("--x-a", type=int); e.add_argument("--x-b", type=int)
    d = sub.add_parser("decrypt"); d.add_argument("file", type=Path); d.add_argument("--out", type=Path)
    a = ap.parse_args()
    try:
        if a.cmd == "encrypt":
            p = a.p or prime(); g = a.g or 2
            xa = a.x_a or secrets.randbelow(p - 2) + 1; xb = a.x_b or secrets.randbelow(p - 2) + 1
            shared = dh_key(p, g, xa, xb); out = a.out or Path(str(a.file) + ".vernam")
            transform(a.file, out, shared)
            Path(str(out) + ".key.json").write_text(json.dumps({"p": p, "g": g, "x_a": xa, "x_b": xb}, indent=2) + "\n", encoding="utf-8")
            print(f"Зашифровано: {out}\np={p}; g={g}; X_A={xa}; X_B={xb}; K={shared}")
        else:
            key = json.loads(Path(str(a.file) + ".key.json").read_text(encoding="utf-8"))
            shared = dh_key(key["p"], key["g"], key["x_a"], key["x_b"])
            out = a.out or Path(str(a.file).removesuffix(".vernam") + ".decrypted")
            transform(a.file, out, shared, b"")
            print(f"Расшифровано: {out}; K={shared}")
    except (ValueError, OSError, KeyError) as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    main()
