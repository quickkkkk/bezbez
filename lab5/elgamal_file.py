"""Учебное шифрование двоичных файлов по схеме Эль-Гамаля."""
from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

MAGIC = b"ELGAMAL1"


def is_probable_prime(n: int) -> bool:
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


def generate_prime(bits: int = 256) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p


def generate_safe_prime(bits: int = 256) -> tuple[int, int]:
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and is_probable_prime(p):
            return p, q


def primitive_root_for_safe_prime(p: int, q: int) -> int:
    # Для p=2q+1 проверок по делителям 2 и q достаточно.
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def encrypt_file(source: Path, target: Path, p: int, g: int, x: int) -> tuple[int, int]:
    if not is_probable_prime(p) or not 1 < g < p or not 1 <= x <= p - 2:
        raise ValueError("Требуются простой p, 1 < g < p и закрытый ключ 1 ≤ x ≤ p−2.")
    data = source.read_bytes()
    # Модуль гарантированно больше любого однобайтового значения.
    if p <= 256:
        raise ValueError("Для шифрования байтов модуль p должен быть больше 256.")
    width = (p.bit_length() + 7) // 8
    chunks = []
    for byte in data:
        k = secrets.randbelow(p - 2) + 1
        c1 = pow(g, k, p)
        c2 = byte * pow(pow(g, x, p), k, p) % p
        chunks.append(c1.to_bytes(width, "big") + c2.to_bytes(width, "big"))
    target.write_bytes(MAGIC + width.to_bytes(2, "big") + p.to_bytes(width, "big") +
                       len(data).to_bytes(8, "big") + b"".join(chunks))
    return pow(g, x, p), x


def decrypt_file(source: Path, target: Path, x: int) -> None:
    raw = source.read_bytes()
    if not raw.startswith(MAGIC) or len(raw) < len(MAGIC) + 10:
        raise ValueError("Неверный формат зашифрованного файла.")
    pos = len(MAGIC); width = int.from_bytes(raw[pos:pos + 2], "big"); pos += 2
    if width < 2 or len(raw) < pos + width + 8:
        raise ValueError("Повреждённый заголовок.")
    p = int.from_bytes(raw[pos:pos + width], "big"); pos += width
    count = int.from_bytes(raw[pos:pos + 8], "big"); pos += 8
    if not is_probable_prime(p) or p <= 256 or not 1 <= x <= p - 2:
        raise ValueError("Неверный модуль или закрытый ключ.")
    if len(raw) - pos != count * width * 2:
        raise ValueError("Размер данных не соответствует заголовку.")
    out = bytearray()
    for offset in range(pos, len(raw), width * 2):
        c1 = int.from_bytes(raw[offset:offset + width], "big")
        c2 = int.from_bytes(raw[offset + width:offset + 2 * width], "big")
        if not (0 < c1 < p and 0 <= c2 < p):
            raise ValueError("Некорректный блок шифротекста.")
        message = c2 * pow(pow(c1, x, p), -1, p) % p
        if message > 255:
            raise ValueError("Неверный ключ или повреждённый файл.")
        out.append(message)
    target.write_bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__); sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt"); e.add_argument("file", type=Path); e.add_argument("--out", type=Path)
    e.add_argument("--p", type=int); e.add_argument("--g", type=int); e.add_argument("--x", type=int, help="закрытый параметр C₂")
    d = sub.add_parser("decrypt"); d.add_argument("file", type=Path); d.add_argument("--out", type=Path); d.add_argument("--x", type=int)
    a = ap.parse_args()
    try:
        if a.cmd == "encrypt":
            if a.p is None and a.g is None and a.x is None:
                mode = input("1 — ввести p, g, C₂; 2 — сгенерировать: ").strip()
                if mode == "1":
                    a.p = int(input("p: ")); a.g = int(input("g: ")); a.x = int(input("C₂ (закрытый ключ): "))
                elif mode != "2":
                    raise ValueError("Неизвестный режим.")
            if a.p is None:
                p, q = generate_safe_prime()
                g = a.g if a.g is not None else primitive_root_for_safe_prime(p, q)
            else:
                p = a.p
                if p <= 256:
                    raise ValueError("Для байтового шифрования p должно быть больше 256.")
                # При ручном p пользователь обычно вводит g; если его нет,
                # случайный ненулевой элемент корректен для самой формулы Эль-Гамаля.
                g = a.g if a.g is not None else secrets.randbelow(p - 3) + 2
            x = a.x if a.x is not None else secrets.randbelow(p - 2) + 1
            out = a.out or Path(str(a.file) + ".elgamal")
            y, x = encrypt_file(a.file, out, p, g, x)
            Path(str(out) + ".key.json").write_text(json.dumps({"p": p, "g": g, "y": y, "x": x}, indent=2) + "\n", encoding="utf-8")
            print(f"Зашифровано: {out}\np={p}; g={g}; открытый ключ D₂={y}; закрытый ключ C₂={x}")
        else:
            x = a.x if a.x is not None else json.loads(Path(str(a.file) + ".key.json").read_text(encoding="utf-8"))["x"]
            out = a.out or Path(str(a.file).removesuffix(".elgamal") + ".decrypted")
            decrypt_file(a.file, out, x); print(f"Расшифровано: {out}")
    except (ValueError, OSError, KeyError) as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    main()
