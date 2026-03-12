import unittest

from ghilliesuite_ex.agents.exploit import _slugify_poc_type, _strip_code_fences


class TestPocUtils(unittest.TestCase):
    def test_slugify_poc_type(self) -> None:
        value = "SQL Injection (Union)!"
        self.assertEqual(_slugify_poc_type(value), "sql_injection_union")

    def test_strip_code_fences_python(self) -> None:
        text = "```python\nprint('hello')\n```"
        self.assertEqual(_strip_code_fences(text), "print('hello')")

    def test_strip_code_fences_plain(self) -> None:
        text = "print('hello')\n"
        self.assertEqual(_strip_code_fences(text), "print('hello')")


if __name__ == "__main__":
    unittest.main()
