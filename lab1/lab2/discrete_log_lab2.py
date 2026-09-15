"""Лабораторная работа №2: дискретный логарифм методом baby-step giant-step.

Функция baby_step_giant_step(a, y, p) ищет x из уравнения:
    y = a**x mod p
для простого p. Время и используемая память: O(sqrt(p)).
"""

from __future__ import annotations

import math
from pathlib import Path
from secrets import SystemRandom
import sys

try:
    from lab1.crypto_library import fermat_primality_test, mod_pow
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lab1.crypto_library import fermat_primality_test, mod_pow

_secure_random = SystemRandom()


def baby_step_giant_step(a: int, y: int, p: int) -> int | None:
    """Возвращает наименьший неотрицательный x, для которого y = a**x mod p.

    Возвращает None, если решения в подгруппе, порождённой a, нет.
    Алгоритм применим к мультипликативной группе по простому модулю p.
    """
    if p < 2 or not fermat_primality_test(p):
        raise ValueError("p должно быть простым числом.")
    if not 0 < a < p:
        raise ValueError("a должно удовлетворять условию 0 < a < p.")
    if not 0 < y < p:
        raise ValueError("y должно удовлетворять условию 0 < y < p.")

    step = math.isqrt(p - 1) + 1

    baby_steps: dict[int, int] = {}
    value = 1
    for j in range(step):
        baby_steps.setdefault(value, j)
        value = (value * a) % p

    giant_factor = pow(mod_pow(a, step, p), -1, p)
    value = y
    for i in range(step + 1):
        if value in baby_steps:
            x = i * step + baby_steps[value]
            if mod_pow(a, x, p) == y:
                return x
        value = (value * giant_factor) % p
    return None


def generate_discrete_log_problem(lower: int = 101, upper: int = 10_000) -> tuple[int, int, int, int]:
    """Создаёт (a, y, p, secret_x), где y = a**secret_x mod p."""
    if lower > upper:
        raise ValueError("Нижняя граница не может быть больше верхней.")

    primes = [n for n in range(max(3, lower), upper + 1) if fermat_primality_test(n)]
    if not primes:
        raise ValueError("В диапазоне нет простых чисел.")

    p = _secure_random.choice(primes)
    a = _secure_random.randrange(2, p)
    secret_x = _secure_random.randrange(0, p - 1)
    y = mod_pow(a, secret_x, p)
    return a, y, p, secret_x


def read_problem() -> tuple[int, int, int]:
    """Считывает a, y и p с клавиатуры."""
    a = int(input("Введите a: "))
    y = int(input("Введите y: "))
    p = int(input("Введите p: "))
    return a, y, p


def main() -> None:
    """Запускает интерактивную демонстрацию поиска дискретного логарифма."""
    print("Дискретный логарифм: шаг младенца, шаг великана")
    print("1 - ввести a, y, p")
    print("2 - сгенерировать a, y, p")
    choice = input("Выберите режим: ").strip()

    try:
        if choice == "1":
            a, y, p = read_problem()
            secret_x = None
        elif choice == "2":
            a, y, p, secret_x = generate_discrete_log_problem()
            print(f"Сгенерировано: a = {a}, y = {y}, p = {p}")
        else:
            print("Неизвестный режим.")
            return

        x = baby_step_giant_step(a, y, p)
    except ValueError as error:
        print(f"Ошибка: {error}")
        return

    if x is None:
        print("Решение не найдено.")
        return

    print(f"x = {x}")
    print(f"Проверка: {a}^{x} mod {p} = {mod_pow(a, x, p)}")
    if secret_x is not None:
        print(f"Исходный сгенерированный показатель: {secret_x}")


if __name__ == "__main__":
    main()
