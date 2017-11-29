import json
import unittest
from typing import List, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.cli import main, Action, NON_BLOCKING_CLI_LONG_PARAMETER, TIMEOUT_CLI_lONG_PARAMETER, \
    SESSION_TTL_CLI_LONG_PARAMETER
from consullock.configuration import SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, DESCRIPTION, MIN_LOCK_TIMEOUT_IN_SECONDS, \
    INVALID_KEY_EXIT_CODE, INVALID_SESSION_TTL_EXIT_CODE
from consullock.json_mappers import ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY, all_capture_builder, set_consul_env
from consullock.tests._test_locks import BaseLockTest, DEFAULT_LOCK_ACQUIRE_TIMEOUT, \
    MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, DOUBLE_SLASH_KEY
from consullock.tests.test_managers import acquire_locks, LockerCallable, action_when_locked, double_action, \
    TestActionTimeoutError


class TestCli(BaseLockTest):
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

    def test_lock_when_unlocked(self):
        lock_result = acquire_locks(TestCli._create_locker())[0]
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        self.assertIsInstance(
            json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder), ConsulLockInformation)

    def test_lock_when_locked_blocking(self):
        lock_result = action_when_locked(TestCli._create_locker())
        self.assertIsInstance(lock_result.exception, TestActionTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = action_when_locked(TestCli._create_locker(action_args=[f"--{NON_BLOCKING_CLI_LONG_PARAMETER}"]))
        self.assertEqual(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, lock_result.exception.code)
        self.assertIsNone(json.loads(lock_result.stdout))

    def test_lock_when_locked_with_timeout(self):
        lock_result = action_when_locked(TestCli._create_locker(
            action_args=[f"--{TIMEOUT_CLI_lONG_PARAMETER}", str(DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2)]))
        self.assertEqual(LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, lock_result.exception.code)
        print(lock_result.stdout)
        self.assertIsNone(json.loads(lock_result.stdout))

    def test_lock_with_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert lock_result.exception.code == SUCCESS_EXIT_CODE

        _, lock_result = double_action(
            TestCli._create_locker(
                action_args=[f"--{SESSION_TTL_CLI_LONG_PARAMETER}", str(MIN_LOCK_TIMEOUT_IN_SECONDS)]),
            TestCli._create_locker(),
            MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR,
            first_lock_callback
        )
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        self.assertIsInstance(
            json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder), ConsulLockInformation)

    def test_lock_with_invalid_session_ttl(self):
        lock_result = acquire_locks(TestCli._create_locker(
            action_args=[f"--{SESSION_TTL_CLI_LONG_PARAMETER}", str(MIN_LOCK_TIMEOUT_IN_SECONDS - 1)]))[0]
        self.assertEqual(INVALID_SESSION_TTL_EXIT_CODE, lock_result.exception.code)

    def test_lock_with_double_slash(self):
        lock_result = acquire_locks(TestCli._create_locker(), [DOUBLE_SLASH_KEY])[0]
        self.assertEqual(INVALID_KEY_EXIT_CODE, lock_result.exception.code)

    def test_unlock_when_unlocked(self):
        with ConsulServiceController().start_service() as service:
            unlock_result = TestCli._unlocker(TEST_KEY, service)
        self.assertEqual(SUCCESS_EXIT_CODE, unlock_result.exception.code)
        self.assertIsNone(json.loads(unlock_result.stdout))

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(TestCli._create_locker(), TestCli._unlocker)
        assert lock_result.exception.code == SUCCESS_EXIT_CODE
        self.assertEqual(SUCCESS_EXIT_CODE, unlock_result.exception.code)
        self.assertEqual(TEST_KEY, json.loads(unlock_result.stdout))

    def test_help(self):
        captured_result = all_capture_builder.build(main)(["-h"])
        self.assertIsInstance(captured_result.exception, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, captured_result.exception.code)
        self.assertIn(DESCRIPTION, captured_result.stdout)

    def test_run_without_consul_in_env(self):
        with self.assertRaises(SystemExit) as e:
            main([Action.UNLOCK.value, TEST_KEY])
        self.assertEqual(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, e.exception.code)

    # def test_unlock_with_regex(self):
    #     with ConsulServiceController().start_service() as service:
    #         consul_lock = ConsulLockManager(consul_client=service.create_consul_client())


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
