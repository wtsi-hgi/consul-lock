import json
import unittest

from consullock.cli import main, Action
from consullock.common import DESCRIPTION
from consullock.configuration import SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE
from consullock.json_mappers import ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY, _EnvironmentPreservingTest, all_capture_builder
from consullock.tests.test_locks import lock_when_unlocked, test_lock_when_locked

from capturewrap import CaptureWrapBuilder, CaptureResult
from useintest.predefined.consul import ConsulDockerisedService


class TestCli(_EnvironmentPreservingTest):
    """
    Tests for the CLI.
    """
    @staticmethod
    def _locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        return all_capture_builder.build(main)([Action.LOCK.value, key])

    @staticmethod
    def _unlocker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        return all_capture_builder.build(main)([Action.UNLOCK.value, key])

    def test_help(self):
        captured_result = all_capture_builder.build(main)(["-h"])
        self.assertIsInstance(captured_result.exception, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, captured_result.exception.code)
        self.assertIn(DESCRIPTION, captured_result.stdout)

    def test_run_without_consul_in_env(self):
        with self.assertRaises(SystemExit) as e:
            main([Action.UNLOCK.value, TEST_KEY])
        self.assertEqual(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, e.exception.code)

    def test_lock_when_unlocked(self):
        lock_result, unlock_result = lock_when_unlocked(self, TestCli._locker, TestCli._unlocker)

        self.assertIsInstance(lock_result.exception, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        self.assertIsInstance(
            json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder), ConsulLockInformation)

        self.assertTrue(json.loads(unlock_result.stdout))

    def test_lock_when_locked(self):
        test_lock_when_locked(self, TestCli._locker)


if __name__ == "__main__":
    unittest.main()
