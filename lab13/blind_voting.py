"""Демонстрация слепой RSA-подписи в простом анонимном голосовании."""
from __future__ import annotations

import hashlib
import json
import math
import secrets

OPTIONS = {"1": "Да", "2": "Нет", "3": "Воздержался"}


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


def prime(bits: int) -> int:
    while True:
        value = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if probable_prime(value):
            return value


def hash_ballot(serial: str, choice: str, n: int) -> int:
    payload = f"lab13-vote-v1|{serial}|{choice}".encode("utf-8")
    value = int.from_bytes(hashlib.sha256(payload).digest(), "big") % n
    return value or 1


class VotingServer:
    """Логическая серверная часть: выдаёт ровно одну слепую подпись на ID."""
    def __init__(self, eligible_voters: set[str], bits: int = 512) -> None:
        e = 65537
        while True:
            p, q = prime(bits), prime(bits)
            phi = (p - 1) * (q - 1)
            if p != q and math.gcd(e, phi) == 1:
                break
        self.p, self.q = p, q
        self.n, self.e, self.d = p * q, e, pow(e, -1, phi)
        self.eligible_voters = eligible_voters
        self.issued: set[str] = set()
        self.used_serials: set[str] = set()
        self.tally = {choice: 0 for choice in OPTIONS.values()}

    def issue_blind_signature(self, voter_id: str, blinded_message: int) -> int:
        if voter_id not in self.eligible_voters:
            raise ValueError("Избиратель не зарегистрирован.")
        if voter_id in self.issued:
            raise ValueError("Этому избирателю бюллетень уже выдан.")
        if not 0 < blinded_message < self.n:
            raise ValueError("Слепое сообщение вне диапазона RSA.")
        self.issued.add(voter_id)
        return pow(blinded_message, self.d, self.n)

    def accept_ballot(self, serial: str, choice: str, signature: int) -> bool:
        if choice not in self.tally or not serial or serial in self.used_serials:
            return False
        message = hash_ballot(serial, choice, self.n)
        if not (0 <= signature < self.n) or pow(signature, self.e, self.n) != message:
            return False
        self.used_serials.add(serial)
        self.tally[choice] += 1
        return True


class VotingClient:
    """Клиент создаёт случайный бюллетень, ослепляет его и снимает ослепление."""
    def __init__(self, server: VotingServer, voter_id: str, choice: str) -> None:
        self.server, self.voter_id, self.choice = server, voter_id, choice
        if choice not in server.tally:
            raise ValueError("Неизвестный вариант голоса.")
        self.serial = secrets.token_hex(16)

    def vote(self) -> dict[str, int | str]:
        server = self.server
        message = hash_ballot(self.serial, self.choice, server.n)
        while True:
            factor = secrets.randbelow(server.n - 2) + 2
            if math.gcd(factor, server.n) == 1:
                break
        blinded = message * pow(factor, server.e, server.n) % server.n
        blind_signature = server.issue_blind_signature(self.voter_id, blinded)
        signature = blind_signature * pow(factor, -1, server.n) % server.n
        return {"serial": self.serial, "choice": self.choice, "message": message,
                "blind_factor": factor, "blinded_message": blinded,
                "blind_signature": blind_signature, "signature": signature}


def main() -> None:
    print("Слепое голосование RSA: варианты 1 — Да, 2 — Нет, 3 — Воздержался")
    try:
        count = int(input("Количество зарегистрированных избирателей: "))
        if count < 1:
            raise ValueError("Количество должно быть положительным.")
        voters = [input(f"ID избирателя {i + 1}: ").strip() for i in range(count)]
        if any(not voter for voter in voters) or len(set(voters)) != len(voters):
            raise ValueError("ID должны быть непустыми и уникальными.")
        server = VotingServer(set(voters))
        print(f"\nПараметры демонстрационного сервера: p={server.p}, q={server.q}")
        print(f"n={server.n}; φ(n)={(server.p - 1) * (server.q - 1)}; e={server.e}; d={server.d}")
        print("В учебном режиме все числа показаны для защиты; в системе голосования d нельзя раскрывать.")
        for voter in voters:
            print(f"\nКлиент {voter}: выберите вариант")
            for key, value in OPTIONS.items():
                print(f"{key} — {value}")
            answer = input("Ваш голос: ").strip()
            if answer not in OPTIONS:
                print("Некорректный вариант; голос не выдан.")
                continue
            client = VotingClient(server, voter, OPTIONS[answer])
            transcript = client.vote()
            accepted = server.accept_ballot(str(transcript["serial"]), str(transcript["choice"]), int(transcript["signature"]))
            print("Передача серверу при выдаче: ID и ослеплённое сообщение.")
            print(f"m={transcript['message']}\nr={transcript['blind_factor']}\nm'={transcript['blinded_message']}")
            print(f"Подпись для m': {transcript['blind_signature']}")
            print("После снятия ослепления бюллетень: " + json.dumps(
                {"serial": transcript["serial"], "choice": transcript["choice"], "signature": transcript["signature"]},
                ensure_ascii=False))
            print("Бюллетень принят." if accepted else "Бюллетень отклонён.")
        print("\nИтоги голосования:")
        for choice, total in server.tally.items():
            print(f"{choice}: {total}")
        print(f"Всего выдано подписей: {len(server.issued)}; принято голосов: {len(server.used_serials)}")
    except (ValueError, EOFError) as exc:
        print(f"Ошибка: {exc}")


if __name__ == "__main__":
    main()
