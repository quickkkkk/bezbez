"""Тесты для crypto_library."""

import math
import unittest

try:
    from .crypto_library import extended_gcd, fermat_primality_test, generate_numbers, mod_pow
except ImportError:
    from crypto_library import extended_gcd, fermat_primality_test, generate_numbers, mod_pow


class CryptoLibraryTests(unittest.TestCase):
    def test_mod_pow(self) -> None:
        self.assertEqual(mod_pow(7, 128, 13), pow(7, 128, 13))
        self.assertEqual(mod_pow(3, 0, 7), 1)

    def test_fermat(self) -> None:
        for number in (2, 3, 5, 97, 997):
            self.assertTrue(fermat_primality_test(number))
        for number in (0, 1, 4, 9, 100):
            self.assertFalse(fermat_primality_test(number))

    def test_extended_gcd(self) -> None:
        for a, b in ((240, 46), (17, 31), (-35, 15), (0, 9)):
            gcd, x, y = extended_gcd(a, b)
            self.assertEqual(gcd, math.gcd(a, b))
            self.assertEqual(a * x + b * y, gcd)

    def test_prime_generation(self) -> None:
        a, b = generate_numbers("prime", 2, 100)
        self.assertTrue(fermat_primality_test(a))
        self.assertTrue(fermat_primality_test(b))


if __name__ == "__main__":
    unittest.main()
