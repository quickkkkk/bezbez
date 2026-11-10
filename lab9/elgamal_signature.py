"""Учебная реализация электронной подписи Эль-Гамаля для файлов."""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path


def is_probable_prime(number: int) -> bool:
    """Вероятностная проверка простоты Миллера—Рабина."""
    if number < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if number == small:
            return True
        if number % small == 0:
            return False

    d = number - 1
    shifts = 0
    while d % 2 == 0:
        d //= 2
        shifts += 1

    for _ in range(32):
        base = secrets.randbelow(number - 3) + 2
        value = pow(base, d, number)
        if value in (1, number - 1):
            continue
        for _ in range(shifts - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 512) -> int:
    """Создаёт случайное нечётное вероятно простое число заданной длины."""
    if bits < 64:
        raise ValueError("Для учебной генерации задайте не менее 64 бит.")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_keys(private_path: Path, public_path: Path, bits: int) -> None:
    """Генерирует параметры, закрытый и открытый ключи."""
    p = generate_prime(bits)
    # Выбираем элемент порядка p-1. Для безопасного простого p достаточно
    # проверить, что g^2 и g^((p-1)/2) не равны 1.
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
            break
    x = secrets.randbelow(p - 3) + 1
    y = pow(g, x, p)
    private_path.write_text(
        json.dumps({"p": p, "g": g, "x": x}, indent=2) + "\n", encoding="utf-8"
    )
    public_path.write_text(
        json.dumps({"p": p, "g": g, "y": y}, indent=2) + "\n", encoding="utf-8"
    )


def file_hash(path: Path, p: int) -> int:
    """SHA-256 содержимого файла, приведённый к диапазону Z_(p-1)."""
    digest = hashlib.sha256(path.read_bytes()).digest()
    return int.from_bytes(digest, "big") % (p - 1)


def sign_file(file_path: Path, private_path: Path, signature_path: Path) -> None:
    key = json.loads(private_path.read_text(encoding="utf-8"))
    p, g, x = (key[name] for name in ("p", "g", "x"))
    message = file_hash(file_path, p)

    while True:
        k = secrets.randbelow(p - 3) + 1
        if __import__("math").gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    s = (k_inverse * (message - x * r)) % (p - 1)

    signature_path.write_text(
        json.dumps(
            {
                "algorithm": "ElGamal signature",
                "hash": "SHA-256",
                "file_sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
                "r": r,
                "s": s,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def verify_file(file_path: Path, public_path: Path, signature_path: Path) -> bool:
    key = json.loads(public_path.read_text(encoding="utf-8"))
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    p, g, y = (key[name] for name in ("p", "g", "y"))
    r, s = signature["r"], signature["s"]
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    message = file_hash(file_path, p)
    return pow(y, r, p) * pow(r, s, p) % p == pow(g, message, p)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="создать пару ключей")
    keygen.add_argument("--private", type=Path, default=Path("private.json"))
    keygen.add_argument("--public", type=Path, default=Path("public.json"))
    keygen.add_argument("--bits", type=int, default=512)

    signer = commands.add_parser("sign", help="подписать файл")
    signer.add_argument("file", type=Path)
    signer.add_argument("--key", type=Path, default=Path("private.json"))
    signer.add_argument("--out", type=Path)

    verifier = commands.add_parser("verify", help="проверить подпись")
    verifier.add_argument("file", type=Path)
    verifier.add_argument("signature", type=Path)
    verifier.add_argument("--key", type=Path, default=Path("public.json"))

    args = parser.parse_args()
    if args.command == "keygen":
        generate_keys(args.private, args.public, args.bits)
        print("Ключи созданы.")
    elif args.command == "sign":
        output = args.out or Path(str(args.file) + ".sig")
        sign_file(args.file, args.key, output)
        print(f"Подпись записана: {output}")
    else:
        valid = verify_file(args.file, args.key, args.signature)
        print("Подпись верна." if valid else "Подпись НЕВЕРНА.")


if __name__ == "__main__":
    main()
