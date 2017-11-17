import unittest

from consullock.cli import main
from consullock.common import DESCRIPTION


class TestCli(unittest.TestCase):
    """
    TODO
    """
    def test_help(self):
        contents = main(["-h"])
        self.assertIn(DESCRIPTION, contents)


if __name__ == "__main__":
    unittest.main()
