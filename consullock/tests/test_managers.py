import unittest
from time import monotonic
from typing import Callable, List, Dict, Any
from unittest.mock import MagicMock, call

from capturewrap import CaptureResult, CaptureWrapBuilder
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.cli import Action
from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration, \
    DEFAULT_LOCK_POLL_INTERVAL_GENERATOR
from consullock.exceptions import DoubleSlashKeyError, InvalidSessionTtlValueError, UnusableStateError, \
    NonNormalisedKeyError, LockAcquireTimeoutError
from consullock.managers import ConsulLockManager, KEY_DIRECTORY_SEPARATOR
from consullock.models import ConsulLockInformation
from consullock.tests._common import KEY_1, KEYS_1, KEYS_2, KEYS_1_REGEX, METADATA, set_consul_env, VALUE_1, \
    ERROR_EXIT_CODE
from consullock.tests._test_locks import BaseLockTest, LockerCallable, acquire_locks, TestActionTimeoutError, \
    action_when_locked, DEFAULT_LOCK_ACQUIRE_TIMEOUT, double_action, MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, \
    DOUBLE_SLASH_KEY, NON_NORMALISED_KEY, single_action

_DUMMY_CONSUL_CONFIGURATION = ConsulConfiguration("")
_DEFAULT_INIT_ARGS_GENERATOR = lambda key, service: []
_DEFAULT_INIT_KWARGS_GENERATOR = lambda key, service: dict(consul_client=service.create_consul_client())


class TestConsulLockManager(BaseLockTest):
    """
    Tests for `ConsulLockManager`.
    """
    _CAPTURE_WRAP_BUILDER = CaptureWrapBuilder(True, True, False)

    @staticmethod
    def _build_executor(
            action: Action,
            init_args_generator: Callable[[str, ConsulDockerisedService], List]=_DEFAULT_INIT_ARGS_GENERATOR,
            init_kwargs_generator: Callable[[str, ConsulDockerisedService], Dict]=_DEFAULT_INIT_KWARGS_GENERATOR,
            action_args: List[Any]=None, action_kwargs: Dict[str, Any]=None) -> LockerCallable:
        action_property = {Action.LOCK: "acquire", Action.EXECUTE: "execute", Action.UNLOCK: "release"}[action]

        def action_executor(key: str, service: ConsulDockerisedService) -> CaptureResult:
            nonlocal init_args_generator, init_kwargs_generator, action_args, action_kwargs, action_property
            lock_manager = ConsulLockManager(*init_args_generator(key, service), **init_kwargs_generator(key, service))
            action_args = action_args if action_args is not None else []
            action_kwargs = action_kwargs if action_kwargs is not None else {}
            return TestConsulLockManager._CAPTURE_WRAP_BUILDER.build(
                getattr(lock_manager, action_property))(key, *action_args, **action_kwargs)
        
        return action_executor

    def test_lock_when_unlocked(self):
        locker = TestConsulLockManager._build_executor(Action.LOCK, action_kwargs=dict(metadata=METADATA))
        seconds_to_test = monotonic()
        lock_result = acquire_locks(locker)[0]
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)
        self.assertGreater(monotonic() - seconds_to_test, lock_result.return_value.seconds_to_lock)
        self.assertEqual(METADATA, lock_result.return_value.metadata)

    def test_lock_with_no_metadata(self):
        locker = TestConsulLockManager._build_executor(Action.LOCK)
        lock_result = acquire_locks(locker)[0]
        self.assertIsNone(lock_result.return_value.metadata)

    def test_lock_when_locked_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._build_executor(Action.LOCK))
        self.assertIsInstance(lock_result.exception, TestActionTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._build_executor(
            Action.LOCK, action_kwargs=dict(blocking=False)))
        self.assertIsNone(lock_result.return_value)

    def test_lock_when_locked_with_timeout(self):
        locker = TestConsulLockManager._build_executor(Action.LOCK, action_kwargs=dict(
            timeout=DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2))
        self.assertRaises(LockAcquireTimeoutError, action_when_locked, locker)

    def test_lock_with_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert isinstance(lock_result.return_value, ConsulLockInformation)

        _, lock_result = double_action(
            TestConsulLockManager._build_executor(
                Action.LOCK, init_kwargs_generator=lambda key, service: dict(
                    **_DEFAULT_INIT_KWARGS_GENERATOR(key, service), session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS)),
            TestConsulLockManager._build_executor(Action.LOCK),
            MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR,
            first_lock_callback
        )
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)

    def test_lock_with_invalid_session_ttl(self):
        self.assertRaises(
            InvalidSessionTtlValueError, ConsulLockManager, session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS - 1,
            consul_configuration=_DUMMY_CONSUL_CONFIGURATION)

    def test_lock_with_double_slash_path(self):
        lock_manager = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        self.assertRaises(DoubleSlashKeyError, lock_manager.acquire, DOUBLE_SLASH_KEY)

    def test_lock_with_non_normalised_path(self):
        lock_manager = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        self.assertRaises(NonNormalisedKeyError, lock_manager.acquire, NON_NORMALISED_KEY)

    def test_unlock_when_unlocked(self):
        with ConsulServiceController().start_service() as service:
            unlock_result = TestConsulLockManager._build_executor(Action.UNLOCK)(KEY_1, service)
        self.assertIsNone(unlock_result.return_value)

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(
            TestConsulLockManager._build_executor(Action.LOCK), TestConsulLockManager._build_executor(Action.UNLOCK))
        assert isinstance(lock_result.return_value, ConsulLockInformation)
        self.assertEqual(KEY_1, unlock_result.return_value)

    def test_unlock_with_regex(self):
        def release(service: ConsulDockerisedService):
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            released_locks = lock_manager.release_regex(KEYS_1_REGEX)
            self.assertCountEqual(KEYS_1, released_locks)

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), KEYS_1 + KEYS_2, release)

    def test_lock_callbacks_when_not_locked(self):
        on_before_lock_listener = MagicMock()
        on_lock_already_locked_listener = MagicMock()

        locker = TestConsulLockManager._build_executor(Action.LOCK, action_kwargs=dict(
            on_before_lock=on_before_lock_listener, on_lock_already_locked=on_lock_already_locked_listener))
        lock_result = acquire_locks(locker)[0]
        assert lock_result.return_value is not None

        on_before_lock_listener.assert_called_once_with(KEY_1)
        on_lock_already_locked_listener.assert_not_called()

    def test_lock_callbacks_when_locked(self):
        on_before_lock_listener = MagicMock()
        on_lock_already_locked_listener = MagicMock()

        locker = TestConsulLockManager._build_executor(Action.LOCK, action_kwargs=dict(
            on_before_lock=on_before_lock_listener, on_lock_already_locked=on_lock_already_locked_listener,
            timeout=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) * 0.5))

        self.assertRaises(LockAcquireTimeoutError, action_when_locked, locker)
        on_before_lock_listener.assert_called_once_with(KEY_1)
        on_lock_already_locked_listener.assert_called_once_with(KEY_1)

    def test_lock_with_lock_poll_interval(self):
        lock_poll_interval_generator = MagicMock(return_value=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) / 4)

        lock_result = action_when_locked(
            TestConsulLockManager._build_executor(Action.LOCK, action_kwargs=dict(
                lock_poll_interval_generator=lock_poll_interval_generator)),
            timeout=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1) / 1.5)
        assert isinstance(lock_result.exception, TestActionTimeoutError)

        lock_poll_interval_generator.assert_has_calls([call(1), call(2)])

    def test_execute_when_not_locked(self):
        result = single_action(TestConsulLockManager._build_executor(
            Action.EXECUTE, action_args=[f"echo {VALUE_1} && exit {ERROR_EXIT_CODE}"],
            action_kwargs=dict(capture_stdout=True, capture_stderr=True)), 1.0)
        return_code, stdout, _ = result.return_value
        self.assertEqual(VALUE_1, stdout.decode("UTF-8").strip())
        self.assertEqual(ERROR_EXIT_CODE, return_code)

    def test_execute_when_not_locked_with_no_output_capture(self):
        result = single_action(TestConsulLockManager._build_executor(
            Action.EXECUTE, action_args=[f"echo {VALUE_1} && exit {ERROR_EXIT_CODE}"],
            action_kwargs=dict(capture_stdout=False, capture_stderr=False)), 1.0)
        return_code, stdout, stderr = result.return_value
        self.assertIsNone(stdout)
        self.assertIsNone(stderr)
        self.assertEqual(VALUE_1, result.stdout.strip())
        self.assertEqual(ERROR_EXIT_CODE, return_code)

    def test_execute_when_locked(self):
        locker = TestConsulLockManager._build_executor(Action.LOCK)
        executor = TestConsulLockManager._build_executor(Action.EXECUTE, action_kwargs=dict(
            executable=[f"exit 0"], blocking=False))
        lock_result, execute_result = double_action(locker, executor)
        assert isinstance(lock_result.return_value, ConsulLockInformation)
        self.assertIsNone(execute_result.return_value[0])

    def test_unlock_all(self):
        test_keys = [f"{KEY_1}_{i}" for i in range(5)]
        with ConsulServiceController().start_service() as service:
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            for key in test_keys:
                lock = lock_manager.acquire(key)
                assert isinstance(lock, ConsulLockInformation)
            unlock_results = lock_manager.release_all(test_keys)
        for unlock_result in unlock_results:
            self.assertTrue(unlock_result)

    def test_cannot_use_after_teardown(self):
        lock_manager = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        lock_manager.teardown()
        self.assertRaises(UnusableStateError, lock_manager.acquire)

    def test_find_when_no_locks(self):
        with ConsulServiceController().start_service() as service:
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            self.assertIsNone(lock_manager.find(KEY_1))

    def test_find_when_locks(self):
        def find(service: ConsulDockerisedService):
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            found_lock = lock_manager.find(KEYS_1[0])
            self.assertEqual(KEYS_1[0], found_lock.key)

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), KEYS_1 + KEYS_2, find)

    def test_find_regex_when_no_locks(self):
        with ConsulServiceController().start_service() as service:
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            found_locks = lock_manager.find_regex(f"{KEY_1}{KEY_DIRECTORY_SEPARATOR}[0-9]+")
            self.assertEqual(0, len(found_locks))

    def test_find_regex_when_locks(self):
        def find_regex(service: ConsulDockerisedService):
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            found_locks = lock_manager.find_regex(KEYS_1_REGEX)
            self.assertCountEqual(KEYS_1, [lock.key for lock in found_locks.values()])

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), KEYS_1 + KEYS_2, find_regex)

    def test_find_regex_when_locks_and_other_key(self):
        def find_regex(service: ConsulDockerisedService):
            consul_client = service.create_consul_client()
            lock_manager = ConsulLockManager(consul_client=consul_client)
            consul_client.kv.put(KEYS_1[1], "unrelated")
            found_locks = lock_manager.find_regex(KEYS_1_REGEX)
            self.assertEqual(2, len(found_locks))
            self.assertIsInstance(found_locks[KEYS_1[0]], ConsulLockInformation)
            self.assertIsNone(found_locks[KEYS_1[1]])

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), [KEYS_1[0]], find_regex)

    def test_can_get_configuration_from_environment(self):
        with ConsulServiceController().start_service() as service:
            set_consul_env(service)
            lock_manager = ConsulLockManager()
            self.assertIsNone(lock_manager.release(KEY_1))

    def test_with_context(self):
        with ConsulServiceController().start_service() as service:
            consul_client = service.create_consul_client()
            lock_manager = ConsulLockManager(consul_client=consul_client)
            with lock_manager.acquire(KEY_1) as lock_information:
                self.assertEqual(lock_information, lock_manager.find(KEY_1))
            self.assertIsNone(lock_manager.find(KEY_1))


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
