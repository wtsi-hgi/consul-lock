import unittest

from consullock.cli import main
from consullock.common import EXECUTABLE_NAME


class MyTestCase(unittest.TestCase):
    def test_something(self):
        main([EXECUTABLE_NAME, "-h"])


if __name__ == "__main__":
    unittest.main()
