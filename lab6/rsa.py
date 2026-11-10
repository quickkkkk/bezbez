import secrets


def gcd(a, b):
    # алгоритм Евклида
    while b:
        a, b = b, a % b

    return a


def extended_gcd(a, b):
    # расширенный алгоритм Евклида
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


def mod_inverse(a, m):
    # обратное число по модулю
    g, x, _ = extended_gcd(a, m)

    if g != 1:
        raise ValueError("Обратного элемента не существует")

    return x % m


def is_prime(n):
    # проверка числа на простоту
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for p in small_primes:
        if n == p:
            return True

        if n % p == 0:
            return False

    # представляем n - 1 в виде d * 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # тест Миллера-Рабина
    for _ in range(10):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits=16):
    # генерируем простое число
    while True:
        number = secrets.randbits(bits)

        # старший бит
        number |= (1 << (bits - 1))

        # число должно быть нечетным
        number |= 1

        if is_prime(number):
            return number


def generate_keys(bits=16):
    # генерируем P и Q
    p = generate_prime(bits)
    q = generate_prime(bits)

    while q == p:
        q = generate_prime(bits)

    # считаем N и функцию Эйлера
    n = p * q
    phi = (p - 1) * (q - 1)

    # выбираем D
    d = 65537

    if d >= phi or gcd(d, phi) != 1:
        d = 3

        while d < phi and gcd(d, phi) != 1:
            d += 2

    # находим C
    c = mod_inverse(d, phi)

    return p, q, n, phi, d, c


def input_keys():
    # вводим параметры с клавиатуры
    print("\nВвод параметров RSA")

    p = int(input("Введите P: "))
    q = int(input("Введите Q: "))
    d = int(input("Введите D: "))

    if not is_prime(p):
        raise ValueError("P должно быть простым числом")

    if not is_prime(q):
        raise ValueError("Q должно быть простым числом")

    if p == q:
        raise ValueError("P и Q должны отличаться")

    # N = P * Q
    n = p * q

    # функция Эйлера
    phi = (p - 1) * (q - 1)

    if d <= 1 or d >= phi:
        raise ValueError("D должно быть больше 1 и меньше φ(N)")

    if gcd(d, phi) != 1:
        raise ValueError("D и φ(N) должны быть взаимно простыми")

    # C * D mod φ = 1
    c = mod_inverse(d, phi)

    return p, q, n, phi, d, c


def get_block_size(n):
    # определяем размер блока
    # чтобы число из блока было меньше N
    block_size = 1

    while 256 ** (block_size + 1) <= n:
        block_size += 1

    return block_size


def encrypt_file(input_filename, output_filename, n, d):
    # шифрование файла
    block_size = get_block_size(n)

    encrypted_block_size = (n.bit_length() + 7) // 8

    print(f"\nРазмер блока: {block_size} байт")

    with open(input_filename, "rb") as source, \
            open(output_filename, "wb") as target:

        while True:
            data = source.read(block_size)

            if not data:
                break

            # переводим байты в число
            m = int.from_bytes(data, byteorder="big")

            # e = m^D mod N
            e = pow(m, d, n)

            # сохраняем размер блока
            target.write(
                len(data).to_bytes(2, "big")
            )

            # сохраняем зашифрованное число
            target.write(
                e.to_bytes(
                    encrypted_block_size,
                    byteorder="big"
                )
            )


def decrypt_file(input_filename, output_filename, n, c):
    # расшифровка файла
    encrypted_block_size = (n.bit_length() + 7) // 8

    with open(input_filename, "rb") as source, \
            open(output_filename, "wb") as target:

        while True:
            # сначала читаем размер блока
            size_data = source.read(2)

            if not size_data:
                break

            if len(size_data) != 2:
                raise ValueError("Поврежденный файл")

            original_size = int.from_bytes(
                size_data,
                byteorder="big"
            )

            # читаем зашифрованный блок
            encrypted_data = source.read(
                encrypted_block_size
            )

            if len(encrypted_data) != encrypted_block_size:
                raise ValueError("Поврежденный файл")

            # переводим обратно в число
            e = int.from_bytes(
                encrypted_data,
                byteorder="big"
            )

            if e >= n:
                raise ValueError(
                    "Файл зашифрован другими ключами"
                )

            # m = e^C mod N
            m = pow(e, c, n)

            try:
                decrypted_data = m.to_bytes(
                    original_size,
                    byteorder="big"
                )
            except OverflowError:
                raise ValueError(
                    "Не удалось расшифровать файл. "
                    "Проверьте ключи."
                )

            target.write(decrypted_data)


def main():

    print("=" * 50)
    print("RSA - ШИФРОВАНИЕ ФАЙЛОВ")
    print("=" * 50)

    print("\nВыберите способ получения параметров:")
    print("1 - Ввести P, Q и D")
    print("2 - Сгенерировать параметры")

    key_mode = input("\nВаш выбор: ")

    try:

        if key_mode == "1":
            p, q, n, phi, d, c = input_keys()

        elif key_mode == "2":
            p, q, n, phi, d, c = generate_keys()

        else:
            print("Неверный выбор")
            return

        print("\nПараметры RSA:")
        print(f"P   = {p}")
        print(f"Q   = {q}")
        print(f"N   = {n}")
        print(f"φ   = {phi}")
        print(f"D   = {d}")
        print(f"C   = {c}")

        print("\nПроверка:")
        print(f"C * D mod φ = {(c * d) % phi}")

        print("\nВыберите операцию:")
        print("1 - Зашифровать файл")
        print("2 - Расшифровать файл")

        operation = input("\nВаш выбор: ")

        if operation == "1":

            input_file = input(
                "Введите путь к исходному файлу: "
            )

            output_file = input(
                "Введите имя зашифрованного файла: "
            )

            encrypt_file(
                input_file,
                output_file,
                n,
                d
            )

            print("\nФайл успешно зашифрован")
            print(f"Результат: {output_file}")

        elif operation == "2":

            input_file = input(
                "Введите путь к зашифрованному файлу: "
            )

            output_file = input(
                "Введите имя расшифрованного файла: "
            )

            decrypt_file(
                input_file,
                output_file,
                n,
                c
            )

            print("\nФайл успешно расшифрован")
            print(f"Результат: {output_file}")

        else:
            print("Неверный выбор")

    except FileNotFoundError:
        print("\nОшибка: файл не найден")

    except ValueError as error:
        print(f"\nОшибка: {error}")


if __name__ == "__main__":
    main()