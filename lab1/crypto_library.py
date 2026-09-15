from __future__ import annotations

import math
from secrets import SystemRandom
from typing import Literal

_secure_random = SystemRandom()


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Возвращает base ** exponent mod modulus методом бинарного возведения."""
    if modulus <= 0:
        raise ValueError("Модуль должен быть положительным числом.")
    if exponent < 0:
        raise ValueError("Показатель степени не может быть отрицательным.")

    result = 1 % modulus
    base %= modulus
    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def fermat_primality_test(n: int, rounds: int = 20) -> bool:
    """Проверяет простоту n с высокой вероятностью тестом Ферма."""
    if rounds < 1:
        raise ValueError("Количество раундов должно быть не меньше 1.")
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for _ in range(rounds):
        a = _secure_random.randrange(2, n - 1)
        if math.gcd(a, n) != 1 or mod_pow(a, n - 1, n) != 1:
            return False
    return True


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Возвращает (gcd, x, y), где a*x + b*y = gcd(a, b)."""
    old_r, remainder = abs(a), abs(b)
    old_x, x = 1, 0
    old_y, y = 0, 1

    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    if a < 0:
        old_x = -old_x
    if b < 0:
        old_y = -old_y
    return old_r, old_x, old_y


def generate_numbers(
    mode: Literal["random", "prime"] = "random", lower: int = 2, upper: int = 10_000
) -> tuple[int, int]:
    """Генерирует два случайных числа либо два вероятно простых числа."""
    if lower > upper:
        raise ValueError("Нижняя граница не может быть больше верхней.")
    if mode == "random":
        return _secure_random.randint(lower, upper), _secure_random.randint(lower, upper)
    if mode != "prime":
        raise ValueError("Режим должен быть 'random' или 'prime'.")

    candidates = [n for n in range(max(2, lower), upper + 1) if fermat_primality_test(n)]
    if not candidates:
        raise ValueError("В заданном диапазоне нет простых чисел.")
    return _secure_random.choice(candidates), _secure_random.choice(candidates)


def read_numbers() -> tuple[int, int]:
    """Считывает два целых числа с клавиатуры."""
    return int(input("Введите a: ")), int(input("Введите b: "))


def main() -> None:
    """Интерактивная демонстрация обобщённого алгоритма Евклида."""
    print("Обобщённый алгоритм Евклида")
    print("1 - ввести a и b")
    print("2 - сгенерировать случайные a и b")
    print("3 - сгенерировать простые a и b")
    choice = input("Выберите режим: ").strip()

    if choice == "1":
        a, b = read_numbers()
    elif choice == "2":
        a, b = generate_numbers("random")
    elif choice == "3":
        a, b = generate_numbers("prime")
    else:
        print("Неизвестный режим.")
        return

    gcd, x, y = extended_gcd(a, b)
    print(f"a = {a}, b = {b}")
    print(f"НОД({a}, {b}) = {gcd}")
    print(f"x = {x}, y = {y}")
    print(f"Проверка: {a} * ({x}) + {b} * ({y}) = {a * x + b * y}")


if __name__ == "__main__":
    main()
