import io
import unittest
from typing import Callable
from unittest.mock import MagicMock

from io import StringIO

from consullock.cli import main, SUCCESS_EXIT_CODE
from consullock.common import DESCRIPTION

from contextlib import redirect_stdout


def _stdout_capture(callable):
    """
    TODO
    :param callable:
    :return:
    """
    def _wrapped(self, *args, **kwargs):
        with redirect_stdout(self._stdout):
            return callable(self, *args, **kwargs)
    return _wrapped


class TestCli(unittest.TestCase):
    """
    Tests for the CLI.
    """
    def setUp(self):
        self._stdout = StringIO()

    @_stdout_capture
    def test_help(self):
        with self.assertRaises(SystemExit) as e:
            main(["-h"])
        self.assertIn(DESCRIPTION, self._stdout.getvalue())
        self.assertEqual(SUCCESS_EXIT_CODE, e.exception.code)


if __name__ == "__main__":
    unittest.main()
