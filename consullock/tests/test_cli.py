import os
import unittest
from copy import deepcopy

from consullock.cli import main, Method
from consullock.common import DESCRIPTION
from consullock.configuration import SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE
from consullock.json_mappers import ConsulLockInformationJSONDecoder
from consullock.tests._common import TEST_KEY, set_consul_env, capture_stdout, capture_stdout_and_stderr
from useintest.predefined.consul import ConsulServiceController

import json
from typing import Tuple

class TestCli(unittest.TestCase):
    """
    Tests for the CLI.
    """
    def setUp(self):
        self._consul_service_controller = ConsulServiceController()
        self._env_cache = deepcopy(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_cache)

    def test_help(self):
        return_value, stdout, _, e = capture_stdout_and_stderr(main, ["-h"])
        self.assertIsInstance(e, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, e.code)
        self.assertIn(DESCRIPTION, stdout)

    def test_run_without_consul_in_env(self):
        with self.assertRaises(SystemExit) as e:
            main([Method.UNLOCK.value, TEST_KEY])
        self.assertEqual(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, e.exception.code)

    def test_lock_and_unlock(self):
        with self._consul_service_controller.start_service() as service:
            set_consul_env(service)
            return_value, stdout, _, e = capture_stdout_and_stderr(main, [Method.LOCK.value, TEST_KEY])
            self.assertIsInstance(e, SystemExit)
            self.assertEqual(SUCCESS_EXIT_CODE, e.code)

            lock_information = json.loads(stdout, cls=ConsulLockInformationJSONDecoder)
            return_value, stdout, _, e = capture_stdout_and_stderr(main, [Method.UNLOCK.value, TEST_KEY])
            # TODO: There should be a value written to stdout...






if __name__ == "__main__":
    unittest.main()
