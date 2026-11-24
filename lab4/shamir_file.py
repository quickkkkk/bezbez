"""Учебный трёхпроходный шифр Шамира для любых двоичных файлов."""
from __future__ import annotations

import argparse
import json
import math
import secrets
from pathlib import Path

MAGIC = b"SHAMIR1\0"


def probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == q:
            return True
        if n % q == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 256) -> int:
    if bits < 16:
        raise ValueError("Для файлового шифрования требуется не менее 16 бит.")
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if probable_prime(p):
            return p


def make_exponent(p: int) -> tuple[int, int]:
    while True:
        c = secrets.randbelow(p - 3) + 2
        if math.gcd(c, p - 1) == 1:
            return c, pow(c, -1, p - 1)


def _params(p: int, c_a: int, c_b: int) -> tuple[int, int]:
    if p <= 256 or not probable_prime(p):
        raise ValueError("p должно быть простым и больше 256.")
    if not (1 < c_a < p - 1 and 1 < c_b < p - 1):
        raise ValueError("Показатели C_A и C_B должны лежать между 1 и p−1.")
    if math.gcd(c_a, p - 1) != 1 or math.gcd(c_b, p - 1) != 1:
        raise ValueError("C_A и C_B должны быть взаимно просты с p−1.")
    return pow(c_a, -1, p - 1), pow(c_b, -1, p - 1)


def encrypt_file(source: Path, target: Path, p: int, c_a: int, c_b: int) -> tuple[int, int]:
    d_a, d_b = _params(p, c_a, c_b)
    data = source.read_bytes()
    width = (p.bit_length() + 7) // 8
    # Два показателя применяются последовательно к каждому байту.
    blocks = b"".join(pow(pow(byte, c_a, p), c_b, p).to_bytes(width, "big") for byte in data)
    target.write_bytes(MAGIC + len(p.to_bytes(width, "big")).to_bytes(2, "big") +
                       p.to_bytes(width, "big") + len(data).to_bytes(8, "big") + blocks)
    return d_a, d_b


def decrypt_file(source: Path, target: Path, d_a: int, d_b: int) -> None:
    raw = source.read_bytes()
    if len(raw) < len(MAGIC) + 10 or not raw.startswith(MAGIC):
        raise ValueError("Неверный формат зашифрованного файла.")
    pos = len(MAGIC)
    p_width = int.from_bytes(raw[pos:pos + 2], "big")
    pos += 2
    if p_width < 2 or len(raw) < pos + p_width + 8:
        raise ValueError("Повреждённый заголовок.")
    p = int.from_bytes(raw[pos:pos + p_width], "big")
    pos += p_width
    length = int.from_bytes(raw[pos:pos + 8], "big")
    pos += 8
    width = (p.bit_length() + 7) // 8
    if not probable_prime(p) or math.gcd(d_a, p - 1) != 1 or math.gcd(d_b, p - 1) != 1:
        raise ValueError("Неверный модуль или параметры расшифрования.")
    if len(raw) - pos != length * width:
        raise ValueError("Размер данных не соответствует заголовку.")
    out = bytearray()
    for offset in range(pos, len(raw), width):
        value = int.from_bytes(raw[offset:offset + width], "big")
        if value >= p:
            raise ValueError("Некорректный блок.")
        out.append(pow(pow(value, d_a, p), d_b, p))
    target.write_bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt"); e.add_argument("file", type=Path); e.add_argument("--out", type=Path)
    e.add_argument("--p", type=int); e.add_argument("--c-a", type=int); e.add_argument("--c-b", type=int)
    d = sub.add_parser("decrypt"); d.add_argument("file", type=Path); d.add_argument("--out", type=Path)
    d.add_argument("--d-a", type=int); d.add_argument("--d-b", type=int)
    a = ap.parse_args()
    try:
        if a.cmd == "encrypt":
            if a.p is None and a.c_a is None and a.c_b is None:
                mode = input("1 — ввести p, C_A, C_B; 2 — сгенерировать: ").strip()
                if mode == "1":
                    a.p = int(input("p: ")); a.c_a = int(input("C_A: ")); a.c_b = int(input("C_B: "))
                elif mode != "2":
                    raise ValueError("Неизвестный режим.")
            p = a.p if a.p is not None else generate_prime()
            if a.c_a is None or a.c_b is None:
                ca, da = make_exponent(p); cb, db = make_exponent(p)
                ca = a.c_a if a.c_a is not None else ca
                cb = a.c_b if a.c_b is not None else cb
                da, db = pow(ca, -1, p - 1), pow(cb, -1, p - 1)
            else:
                ca, cb = a.c_a, a.c_b
                da, db = _params(p, ca, cb)
            out = a.out or Path(str(a.file) + ".shamir")
            da, db = encrypt_file(a.file, out, p, ca, cb)
            keyfile = Path(str(out) + ".keys.json")
            keyfile.write_text(json.dumps({"p": p, "d_a": da, "d_b": db}, indent=2) + "\n", encoding="utf-8")
            print(f"Зашифровано: {out}\nСекретные параметры расшифрования: {keyfile}")
            print(f"p={p}; C_A={ca}; C_B={cb}; D_A={da}; D_B={db}")
        else:
            if a.d_a is None or a.d_b is None:
                key = json.loads(Path(str(a.file) + ".keys.json").read_text(encoding="utf-8"))
                da, db = key["d_a"], key["d_b"]
            else:
                da, db = a.d_a, a.d_b
            out = a.out or Path(str(a.file).removesuffix(".shamir") + ".decrypted")
            decrypt_file(a.file, out, da, db)
            print(f"Расшифровано: {out}")
    except (ValueError, OSError, KeyError) as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    main()
