import json
import os
import shutil
import unittest
from os import chmod
from tempfile import mkdtemp
from typing import List, Any, Optional

import itertools
from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.cli import main, Action, NON_BLOCKING_CLI_LONG_PARAMETER, TIMEOUT_CLI_lONG_PARAMETER, \
    SESSION_TTL_CLI_LONG_PARAMETER, REGEX_KEY_ENABLED_SHORT_PARAMETER, METADATA_CLI_lONG_PARAMETER, \
    ON_BEFORE_LOCK_LONG_PARAMETER, ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER, LOCK_POLL_INTERVAL_SHORT_PARAMETER
from consullock.configuration import SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, DESCRIPTION, MIN_LOCK_TIMEOUT_IN_SECONDS, \
    INVALID_KEY_EXIT_CODE, INVALID_SESSION_TTL_EXIT_CODE, VERSION, DEFAULT_LOCK_POLL_INTERVAL_GENERATOR
from consullock.json_mappers import ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY, all_capture_builder, set_consul_env, TEST_KEYS, TEST_KEYS_2, \
    TEST_KEYS_REGEX, TEST_METADATA
from consullock.tests._test_locks import BaseLockTest, DEFAULT_LOCK_ACQUIRE_TIMEOUT, \
    MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, DOUBLE_SLASH_KEY, NON_NORMALISED_KEY
from consullock.tests.test_managers import acquire_locks, LockerCallable, action_when_locked, double_action, \
    TestActionTimeoutError

_BASH_SHEBANG = "#!/usr/bin/env bash"
_END_OF_CLI_KEYWORD_OPTIONS = "--"


class TestCli(BaseLockTest):
    """
    Tests for the CLI.
    """
    @staticmethod
    def _build_executor(action: Action, main_args: List[Any]=None, action_args: List[Any]=None) \
            -> LockerCallable:
        main_args = [str(arg) for arg in main_args] if main_args is not None else []
        action_args = [str(arg) for arg in action_args] if action_args is not None else []

        def action_executor(key: str, service: ConsulDockerisedService) -> CaptureResult:
            set_consul_env(service)
            return all_capture_builder.build(main)(main_args + [action.value] + action_args + [key])

        return action_executor

    def setUp(self):
        super().setUp()
        self.temp_directories: List[str] = []

    def tearDown(self):
        super().tearDown()
        for file in self.temp_directories:
            shutil.rmtree(file)

    def test_lock_when_unlocked(self):
        lock_result = acquire_locks(TestCli._build_executor(
            Action.LOCK, action_args=[f"--{METADATA_CLI_lONG_PARAMETER}", json.dumps(TEST_METADATA)]))[0]
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        parsed_stdout = json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder)
        self.assertIsInstance(parsed_stdout, ConsulLockInformation)
        self.assertEqual(TEST_METADATA, parsed_stdout.metadata)

    def test_lock_when_locked_blocking(self):
        lock_result = action_when_locked(TestCli._build_executor(Action.LOCK))
        self.assertIsInstance(lock_result.exception, TestActionTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = action_when_locked(TestCli._build_executor(
            Action.LOCK, action_args=[f"--{NON_BLOCKING_CLI_LONG_PARAMETER}"]))
        self.assertEqual(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, lock_result.exception.code)
        self.assertIsNone(json.loads(lock_result.stdout))

    def test_lock_when_locked_with_timeout(self):
        lock_result = action_when_locked(TestCli._build_executor(
            Action.LOCK, action_args=[f"--{TIMEOUT_CLI_lONG_PARAMETER}", DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2]))
        self.assertEqual(LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, lock_result.exception.code)
        print(lock_result.stdout)
        self.assertIsNone(json.loads(lock_result.stdout))

    def test_lock_with_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert lock_result.exception.code == SUCCESS_EXIT_CODE

        _, lock_result = double_action(
            TestCli._build_executor(
                Action.LOCK, action_args=[f"--{SESSION_TTL_CLI_LONG_PARAMETER}", MIN_LOCK_TIMEOUT_IN_SECONDS]),
            TestCli._build_executor(Action.LOCK),
            MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR,
            first_lock_callback
        )
        self.assertEqual(SUCCESS_EXIT_CODE, lock_result.exception.code)
        self.assertIsInstance(
            json.loads(lock_result.stdout, cls=ConsulLockInformationJSONDecoder), ConsulLockInformation)

    def test_lock_with_invalid_session_ttl(self):
        lock_result = acquire_locks(TestCli._build_executor(
            Action.LOCK, action_args=[f"--{SESSION_TTL_CLI_LONG_PARAMETER}", MIN_LOCK_TIMEOUT_IN_SECONDS - 1]))[0]
        self.assertEqual(INVALID_SESSION_TTL_EXIT_CODE, lock_result.exception.code)

    def test_lock_with_double_slash_path(self):
        lock_result = acquire_locks(TestCli._build_executor(Action.LOCK), [DOUBLE_SLASH_KEY])[0]
        self.assertEqual(INVALID_KEY_EXIT_CODE, lock_result.exception.code)

    def test_lock_with_non_normalised_path(self):
        lock_result = acquire_locks(TestCli._build_executor(Action.LOCK), [NON_NORMALISED_KEY])[0]
        self.assertEqual(INVALID_KEY_EXIT_CODE, lock_result.exception.code)

    def test_unlock_when_unlocked(self):
        with ConsulServiceController().start_service() as service:
            unlock_result = TestCli._build_executor(Action.UNLOCK)(TEST_KEY, service)
        self.assertEqual(SUCCESS_EXIT_CODE, unlock_result.exception.code)
        self.assertIsNone(json.loads(unlock_result.stdout))

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(
            TestCli._build_executor(Action.LOCK), TestCli._build_executor(Action.UNLOCK))
        assert lock_result.exception.code == SUCCESS_EXIT_CODE
        self.assertEqual(SUCCESS_EXIT_CODE, unlock_result.exception.code)
        self.assertEqual(TEST_KEY, json.loads(unlock_result.stdout))

    def test_help(self):
        captured_result = all_capture_builder.build(main)(["-h"])
        self.assertIsInstance(captured_result.exception, SystemExit)
        self.assertEqual(SUCCESS_EXIT_CODE, captured_result.exception.code)
        self.assertIn(DESCRIPTION, captured_result.stdout)
        self.assertIn(VERSION, captured_result.stdout)

    def test_run_without_consul_in_env(self):
        with self.assertRaises(SystemExit) as e:
            main([Action.UNLOCK.value, TEST_KEY])
        self.assertEqual(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, e.exception.code)

    def test_unlock_with_regex(self):
        def release(service: ConsulDockerisedService):
            set_consul_env(service)
            captured_result = all_capture_builder.build(main)(
                [Action.UNLOCK.value, f"-{REGEX_KEY_ENABLED_SHORT_PARAMETER}", TEST_KEYS_REGEX])
            self.assertEqual(SUCCESS_EXIT_CODE, captured_result.exception.code)
            self.assertCountEqual(TEST_KEYS, json.loads(captured_result.stdout))

        acquire_locks(TestCli._build_executor(Action.LOCK), TEST_KEYS + TEST_KEYS_2, release)

    def test_lock_callbacks_when_not_locked(self):
        on_before_lock_listeners = [self._create_magic_mock_file() for _ in range(3)]
        on_lock_already_locked_listeners = [self._create_magic_mock_file() for _ in range(3)]

        action_args = [
            *itertools.chain(*[[f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", listener]
                               for listener in on_before_lock_listeners]),
            *itertools.chain(*[[f"--{ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER}", listener]
                               for listener in on_lock_already_locked_listeners]),
            _END_OF_CLI_KEYWORD_OPTIONS]
        locker = TestCli._build_executor(Action.LOCK, action_args=action_args)

        lock_result = acquire_locks(locker)[0]
        assert lock_result.exception.code == SUCCESS_EXIT_CODE
        for listener in on_before_lock_listeners:
            self.assertEqual([TEST_KEY], self._get_magic_mock_results(listener))
        for listener in on_lock_already_locked_listeners:
            self.assertIsNone(self._get_magic_mock_results(listener))

    def test_lock_callbacks_when_locked(self):
        on_before_lock_listener = self._create_magic_mock_file()
        on_lock_already_locked_listener = self._create_magic_mock_file()

        locker = TestCli._build_executor(Action.LOCK, action_args=[
            f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", on_before_lock_listener,
            f"--{ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER}", on_lock_already_locked_listener,
            f"--{TIMEOUT_CLI_lONG_PARAMETER}", DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) * 0.5,
            _END_OF_CLI_KEYWORD_OPTIONS])

        lock_result = action_when_locked(locker)
        assert lock_result.exception.code == LOCK_ACQUIRE_TIMEOUT_EXIT_CODE
        self.assertEqual([TEST_KEY], self._get_magic_mock_results(on_before_lock_listener))
        self.assertEqual([TEST_KEY], self._get_magic_mock_results(on_lock_already_locked_listener))

    def test_lock_with_lock_poll_interval(self):
        on_before_lock_listener = self._create_magic_mock_file()

        lock_result = action_when_locked(
            TestCli._build_executor(Action.LOCK, action_args=[
                f"-{LOCK_POLL_INTERVAL_SHORT_PARAMETER}", DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) / 4,
                f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", on_before_lock_listener,
                _END_OF_CLI_KEYWORD_OPTIONS]),
            timeout=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) / 1.5)
        assert isinstance(lock_result.exception, TestActionTimeoutError)

        self.assertGreaterEqual(len(self._get_magic_mock_results(on_before_lock_listener)), 2)

    def test_lock_callback_when_callback_fails(self):
        on_before_lock_listener = self._create_magic_mock_file()
        with open(on_before_lock_listener, "w") as file:
            file.write(f"{_BASH_SHEBANG}\nexit 1")

        locker = TestCli._build_executor(
            Action.LOCK, action_args=[
                f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", on_before_lock_listener, _END_OF_CLI_KEYWORD_OPTIONS])
        lock_result = acquire_locks(locker)[0]
        assert lock_result.exception.code == SUCCESS_EXIT_CODE

    def _create_magic_mock_file(self):
        """
        TODO
        :return:
        """
        temp_directory = mkdtemp()
        self.temp_directories.append(temp_directory)
        file_location = os.path.join(temp_directory, "executable")
        with open(file_location, "w") as file:
            file.write(f"{_BASH_SHEBANG}\necho $@ >> {self._get_magic_mock_file_results_location(file_location)}")
        chmod(file_location, 0o700)
        return file_location

    def _get_magic_mock_file_results_location(self, file_location: str) -> str:
        """
        TODO
        :param file_location:
        :return:
        """
        return f"{file_location}.results"

    def _get_magic_mock_results(self, file_location: str) -> Optional[List[str]]:
        """
        TODO
        :param file_location:
        :return:
        """
        try:
            with open(self._get_magic_mock_file_results_location(file_location), "r") as file:
                return file.read().splitlines()
        except FileNotFoundError:
            return None


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
