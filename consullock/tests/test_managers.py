import unittest
from typing import Callable, List, Dict, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.cli import Action
from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration
from consullock.exceptions import DoubleSlashKeyError, InvalidSessionTtlValueError, UnusableStateError
from consullock.managers import ConsulLockManager, KEY_DIRECTORY_SEPARATOR
from consullock.models import ConsulLockInformation
from consullock.tests._common import all_capture_builder, TEST_KEY, TEST_KEYS, TEST_KEYS_2, TEST_KEYS_REGEX
from consullock.tests._test_locks import BaseLockTest, LockerCallable, acquire_locks, TestActionTimeoutError, \
    action_when_locked, DEFAULT_LOCK_ACQUIRE_TIMEOUT, double_action, MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, \
    DOUBLE_SLASH_KEY

_DUMMY_CONSUL_CONFIGURATION = ConsulConfiguration("")
_DEFAULT_INIT_ARGS_GENERATOR = lambda key, service: []
_DEFAULT_INIT_KWARGS_GENERATOR = lambda key, service: dict(consul_client=service.create_consul_client())


class TestConsulLockManager(BaseLockTest):
    """
    Tests for `ConsulLockManager`.
    """
    @staticmethod
    def _build_executor(
            action: Action,
            init_args_generator: Callable[[str, ConsulDockerisedService], List]=_DEFAULT_INIT_ARGS_GENERATOR,
            init_kwargs_generator: Callable[[str, ConsulDockerisedService], Dict]=_DEFAULT_INIT_KWARGS_GENERATOR,
            action_args: List[Any]=None, action_kwargs: Dict[str, Any]=None) -> LockerCallable:
        action_property = "acquire" if action == Action.LOCK else "release"

        def action_executor(key: str, service: ConsulDockerisedService) -> CaptureResult:
            nonlocal init_args_generator, init_kwargs_generator, action_args, action_kwargs, action_property
            lock_manager = ConsulLockManager(*init_args_generator(key, service), **init_kwargs_generator(key, service))
            action_args = action_args if action_args is not None else []
            action_kwargs = action_kwargs if action_kwargs is not None else {}
            return all_capture_builder.build(getattr(lock_manager, action_property))(key, *action_args, **action_kwargs)
        
        return action_executor

    def test_lock_when_unlocked(self):
        lock_result = acquire_locks(TestConsulLockManager._build_executor(Action.LOCK))[0]
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)

    def test_lock_when_locked_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._build_executor(Action.LOCK))
        self.assertIsInstance(lock_result.exception, TestActionTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._build_executor(
            Action.LOCK, action_kwargs=dict(blocking=False)))
        self.assertIsNone(lock_result.return_value)

    def test_lock_when_locked_with_timeout(self):
        lock_result = action_when_locked(TestConsulLockManager._build_executor(
            Action.LOCK, action_kwargs=dict(timeout=DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2)))
        self.assertIsNone(lock_result.return_value)

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

    def test_lock_with_double_slash(self):
        lock_manager = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        self.assertRaises(DoubleSlashKeyError, lock_manager.acquire, DOUBLE_SLASH_KEY)

    def test_unlock_when_unlocked(self):
        with ConsulServiceController().start_service() as service:
            unlock_result = TestConsulLockManager._build_executor(Action.UNLOCK)(TEST_KEY, service)
        self.assertIsNone(unlock_result.return_value)

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(
            TestConsulLockManager._build_executor(Action.LOCK), TestConsulLockManager._build_executor(Action.UNLOCK))
        assert isinstance(lock_result.return_value, ConsulLockInformation)
        self.assertEqual(TEST_KEY, unlock_result.return_value)

    def test_unlock_all(self):
        test_keys = [f"{TEST_KEY}_{i}" for i in range(5)]
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
            found_locks = lock_manager.find(f"{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}[0-9]+")
            self.assertEqual(0, len(found_locks))

    def test_find_when_locks(self):
        def find(service: ConsulDockerisedService):
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            found_locks = lock_manager.find(TEST_KEYS_REGEX)
            self.assertCountEqual(TEST_KEYS, [lock.key for lock in found_locks.values()])

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), TEST_KEYS + TEST_KEYS_2, find)

    def test_find_when_locks_and_other_key(self):
        def find(service: ConsulDockerisedService):
            consul_client = service.create_consul_client()
            lock_manager = ConsulLockManager(consul_client=consul_client)
            consul_client.kv.put(TEST_KEYS[1], "unrelated")
            found_locks = lock_manager.find(TEST_KEYS_REGEX)
            self.assertEqual(2, len(found_locks))
            self.assertIsInstance(found_locks[TEST_KEYS[0]], ConsulLockInformation)
            self.assertIsNone(found_locks[TEST_KEYS[1]])

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), [TEST_KEYS[0]], find)

    def test_unlock_with_regex(self):
        def release(service: ConsulDockerisedService):
            lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
            released_locks = lock_manager.release_regex(TEST_KEYS_REGEX)
            self.assertCountEqual(TEST_KEYS, released_locks)

        acquire_locks(TestConsulLockManager._build_executor(Action.LOCK), TEST_KEYS + TEST_KEYS_2, release)


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
