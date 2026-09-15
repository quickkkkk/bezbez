"""Тесты лабораторной работы №2."""

import unittest

try:
    from .discrete_log_lab2 import baby_step_giant_step, generate_discrete_log_problem
except ImportError:
    from discrete_log_lab2 import baby_step_giant_step, generate_discrete_log_problem


class BabyStepGiantStepTests(unittest.TestCase):
    def test_finds_known_discrete_logarithm(self) -> None:
        self.assertEqual(baby_step_giant_step(2, 8, 13), 3)
        self.assertEqual(baby_step_giant_step(5, 18, 23), 12)

    def test_finds_zero_exponent(self) -> None:
        self.assertEqual(baby_step_giant_step(7, 1, 29), 0)

    def test_returns_none_when_no_solution_exists(self) -> None:
        self.assertIsNone(baby_step_giant_step(4, 3, 7))

    def test_generated_problem_is_solved(self) -> None:
        a, y, p, secret_x = generate_discrete_log_problem(101, 200)
        result = baby_step_giant_step(a, y, p)
        self.assertIsNotNone(result)
        self.assertEqual(pow(a, result, p), y)
        self.assertEqual(pow(a, secret_x, p), y)

    def test_rejects_non_prime_modulus(self) -> None:
        with self.assertRaises(ValueError):
            baby_step_giant_step(2, 3, 15)


if __name__ == "__main__":
    unittest.main()
