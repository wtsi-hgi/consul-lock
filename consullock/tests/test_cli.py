import json
import unittest
from typing import List, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService

from consullock.cli import main, Action, NON_BLOCKING_CLI_LONG_PARAMETER
from consullock.common import DESCRIPTION
from consullock.configuration import SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE
from consullock.json_mappers import ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY, _EnvironmentPreservingTest, all_capture_builder, set_consul_env
from consullock.tests.test_locks import lock_when_unlocked, test_lock_when_locked, \
    test_lock_with_blocking_when_locked, LockerCallable


class TestCli(_EnvironmentPreservingTest):
    """
    Tests for the CLI.
    """
    @staticmethod
    def _create_locker(main_args: List[Any]=None, action_args: List[Any]=None) -> LockerCallable:
        main_args = main_args or []
        action_args = action_args or []

        def locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
            set_consul_env(service)
            return all_capture_builder.build(main)(main_args + [Action.LOCK.value, key] + action_args)

        return locker

    @staticmethod
    def _unlocker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        set_consul_env(service)
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
        lock_result, unlock_result = lock_when_unlocked(self, TestCli._create_locker(), TestCli._unlocker)

        self.assertIsInstance(lock_result.exception, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        self.assertIsInstance(
            json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder), ConsulLockInformation)

        self.assertTrue(json.loads(unlock_result.stdout))

    def test_lock_when_locked(self):
        test_lock_when_locked(self, TestCli._create_locker())

    def test_lock_when_locked_with_blocking(self):
        lock_result = test_lock_with_blocking_when_locked(
            self, TestCli._create_locker(action_args=[f"--{NON_BLOCKING_CLI_LONG_PARAMETER}"]))
        self.assertEqual(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, lock_result.exception.code)
        self.assertIsNone(json.loads(lock_result.stdout))


if __name__ == "__main__":
    unittest.main()
