"""Лабораторная работа №3: построение общего ключа Диффи-Хеллмана."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from secrets import SystemRandom
import sys

try:
    from lab1.crypto_library import fermat_primality_test, mod_pow
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lab1.crypto_library import fermat_primality_test, mod_pow

_secure_random = SystemRandom()


@dataclass(frozen=True)
class DiffieHellmanResult:
    """Параметры обмена и одинаковый общий секрет двух абонентов."""

    p: int
    g: int
    private_a: int
    private_b: int
    public_a: int
    public_b: int
    shared_key_a: int
    shared_key_b: int

    @property
    def shared_key(self) -> int:
        """Возвращает общий ключ после проверки равенства результатов."""
        if self.shared_key_a != self.shared_key_b:
            raise RuntimeError("Абоненты получили разные ключи.")
        return self.shared_key_a


def _prime_factors(number: int) -> set[int]:
    """Возвращает множество простых делителей положительного числа."""
    factors: set[int] = set()
    divisor = 2
    while divisor * divisor <= number:
        while number % divisor == 0:
            factors.add(divisor)
            number //= divisor
        divisor += 1 if divisor == 2 else 2
    if number > 1:
        factors.add(number)
    return factors


def is_primitive_root(g: int, p: int) -> bool:
    """Проверяет, является ли g первообразным корнем по модулю простого p."""
    if not fermat_primality_test(p) or not 1 < g < p:
        return False
    return all(mod_pow(g, (p - 1) // factor, p) != 1 for factor in _prime_factors(p - 1))


def find_primitive_root(p: int) -> int:
    """Находит наименьший первообразный корень по простому модулю p."""
    if p < 3 or not fermat_primality_test(p):
        raise ValueError("p должно быть простым числом не меньше 3.")
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    raise RuntimeError("Не удалось найти первообразный корень.")


def build_shared_key(p: int, g: int, private_a: int, private_b: int) -> DiffieHellmanResult:
    """Строит общий ключ двух абонентов по схеме Диффи-Хеллмана.

    p - простой модуль, g - первообразный корень по модулю p,
    private_a и private_b - секретные показатели абонентов.
    """
    if p < 3 or not fermat_primality_test(p):
        raise ValueError("p должно быть простым числом не меньше 3.")
    if not is_primitive_root(g, p):
        raise ValueError("g должно быть первообразным корнем по модулю p.")
    if not 1 <= private_a <= p - 2 or not 1 <= private_b <= p - 2:
        raise ValueError("Секретные показатели должны лежать в диапазоне от 1 до p - 2.")

    public_a = mod_pow(g, private_a, p)
    public_b = mod_pow(g, private_b, p)
    shared_key_a = mod_pow(public_b, private_a, p)
    shared_key_b = mod_pow(public_a, private_b, p)

    return DiffieHellmanResult(
        p, g, private_a, private_b, public_a, public_b, shared_key_a, shared_key_b
    )


def generate_diffie_hellman_parameters(
    lower: int = 101, upper: int = 10_000
) -> tuple[int, int, int, int]:
    """Генерирует p, g, private_a и private_b для учебного обмена."""
    if lower > upper:
        raise ValueError("Нижняя граница не может быть больше верхней.")

    primes = [n for n in range(max(3, lower), upper + 1) if fermat_primality_test(n)]
    if not primes:
        raise ValueError("В диапазоне нет подходящих простых чисел.")

    p = _secure_random.choice(primes)
    g = find_primitive_root(p)
    private_a = _secure_random.randrange(1, p - 1)
    private_b = _secure_random.randrange(1, p - 1)
    return p, g, private_a, private_b


def read_parameters() -> tuple[int, int, int, int]:
    """Считывает p, g и секретные показатели двух абонентов."""
    p = int(input("Введите p: "))
    g = int(input("Введите g: "))
    private_a = int(input("Введите секретный показатель первого абонента X1: "))
    private_b = int(input("Введите секретный показатель второго абонента X2: "))
    return p, g, private_a, private_b


def print_result(result: DiffieHellmanResult) -> None:
    """Выводит вычисленные параметры обмена."""
    print(f"p = {result.p}, g = {result.g}")
    print(f"Открытый ключ первого абонента: A = {result.public_a}")
    print(f"Открытый ключ второго абонента: B = {result.public_b}")
    print(f"Ключ первого абонента: K1 = {result.shared_key_a}")
    print(f"Ключ второго абонента: K2 = {result.shared_key_b}")
    print(f"Общий ключ: K = {result.shared_key}")


def main() -> None:
    """Запускает интерактивную демонстрацию обмена Диффи-Хеллмана."""
    print("Построение общего ключа по схеме Диффи-Хеллмана")
    print("1 - ввести p, g, X1, X2")
    print("2 - сгенерировать параметры")
    choice = input("Выберите режим: ").strip()

    try:
        if choice == "1":
            parameters = read_parameters()
        elif choice == "2":
            parameters = generate_diffie_hellman_parameters()
            print("Параметры сгенерированы.")
        else:
            print("Неизвестный режим.")
            return
        print_result(build_shared_key(*parameters))
    except ValueError as error:
        print(f"Ошибка: {error}")


if __name__ == "__main__":
    main()
