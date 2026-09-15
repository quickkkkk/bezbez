"""Тесты лабораторной работы №3."""

import unittest

try:
    from .diffie_hellman_lab3 import (
        build_shared_key,
        find_primitive_root,
        generate_diffie_hellman_parameters,
        is_primitive_root,
    )
except ImportError:
    from diffie_hellman_lab3 import (
        build_shared_key,
        find_primitive_root,
        generate_diffie_hellman_parameters,
        is_primitive_root,
    )


class DiffieHellmanTests(unittest.TestCase):
    def test_known_exchange(self) -> None:
        result = build_shared_key(23, 5, 6, 15)
        self.assertEqual(result.public_a, 8)
        self.assertEqual(result.public_b, 19)
        self.assertEqual(result.shared_key, 2)
        self.assertEqual(result.shared_key_a, result.shared_key_b)

    def test_primitive_root(self) -> None:
        self.assertTrue(is_primitive_root(5, 23))
        self.assertFalse(is_primitive_root(4, 23))
        self.assertEqual(find_primitive_root(23), 5)

    def test_generated_parameters(self) -> None:
        p, g, private_a, private_b = generate_diffie_hellman_parameters(101, 200)
        result = build_shared_key(p, g, private_a, private_b)
        self.assertTrue(is_primitive_root(g, p))
        self.assertEqual(result.shared_key_a, result.shared_key_b)

    def test_invalid_parameters(self) -> None:
        with self.assertRaises(ValueError):
            build_shared_key(15, 2, 3, 4)
        with self.assertRaises(ValueError):
            build_shared_key(23, 4, 3, 4)


if __name__ == "__main__":
    unittest.main()
