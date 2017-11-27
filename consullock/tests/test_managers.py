import unittest
from typing import Callable, List, Dict, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration
from consullock.exceptions import DoubleSlashKeyError, InvalidSessionTtlValueError, UnusableStateError
from consullock.managers import ConsulLockManager
from consullock.models import ConsulLockInformation
from consullock.tests._common import all_capture_builder, TEST_KEY
from consullock.tests._test_locks import BaseLockTest, DEFAULT_LOCK_INIT_ARGS_GENERATOR, \
    DEFAULT_LOCK_INIT_KWARGS_GENERATOR, \
    LockerCallable, acquire_locks, TestActionTimeoutError, action_when_locked, DEFAULT_LOCK_ACQUIRE_TIMEOUT, \
    double_action, MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, DOUBLE_SLASH_KEY

_DUMMY_CONSUL_CONFIGURATION = ConsulConfiguration("")


class TestConsulLockManager(BaseLockTest):
    """
    Tests for `ConsulLockManager`.
    """
    @staticmethod
    def _create_locker(
            lock_init_args: Callable[[str, ConsulDockerisedService], List]=DEFAULT_LOCK_INIT_ARGS_GENERATOR,
            lock_init_kwargs: Callable[[str, ConsulDockerisedService], Dict]=DEFAULT_LOCK_INIT_KWARGS_GENERATOR,
            acquire_args: List[Any]=None, acquire_kwargs: Dict[str, Any]=None) -> LockerCallable:
        def _locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
            nonlocal acquire_args, acquire_kwargs
            consul_lock = ConsulLockManager(*lock_init_args(key, service), **lock_init_kwargs(key, service))
            acquire_args = acquire_args if acquire_args is not None else []
            acquire_kwargs = acquire_kwargs if acquire_kwargs is not None else {}
            return all_capture_builder.build(consul_lock.acquire)(key, *acquire_args, **acquire_kwargs)
        return _locker

    @staticmethod
    def _unlocker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
        return all_capture_builder.build(consul_lock.release)(key)

    def test_lock_when_unlocked(self):
        lock_result = acquire_locks(TestConsulLockManager._create_locker())[0]
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)

    def test_lock_when_locked_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._create_locker())
        self.assertIsInstance(lock_result.exception, TestActionTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = action_when_locked(TestConsulLockManager._create_locker(acquire_kwargs=dict(blocking=False)))
        self.assertIsNone(lock_result.return_value)

    def test_lock_when_locked_with_timeout(self):
        lock_result = action_when_locked(TestConsulLockManager._create_locker(
            acquire_kwargs=dict(timeout=DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2)))
        self.assertIsNone(lock_result.return_value)

    def test_lock_with_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert isinstance(lock_result.return_value, ConsulLockInformation)

        _, lock_result = double_action(
            TestConsulLockManager._create_locker(lock_init_kwargs=lambda key, service: dict(
                **DEFAULT_LOCK_INIT_KWARGS_GENERATOR(key, service),
                session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS)),
            TestConsulLockManager._create_locker(),
            MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR,
            first_lock_callback
        )
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)

    def test_lock_with_invalid_session_ttl(self):
        self.assertRaises(
            InvalidSessionTtlValueError, ConsulLockManager, session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS - 1,
            consul_configuration=_DUMMY_CONSUL_CONFIGURATION)

    def test_lock_with_double_slash(self):
        consul_lock = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        self.assertRaises(DoubleSlashKeyError, consul_lock.acquire, DOUBLE_SLASH_KEY)

    def test_unlock_when_unlocked(self):
        with ConsulServiceController().start_service() as service:
            unlock_result = TestConsulLockManager._unlocker(TEST_KEY, service)
        self.assertFalse(unlock_result.return_value)

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(
            TestConsulLockManager._create_locker(), TestConsulLockManager._unlocker)
        assert isinstance(lock_result.return_value, ConsulLockInformation)
        self.assertTrue(unlock_result.return_value)

    def test_cannot_use_after_teardown(self):
        consul_lock = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        consul_lock.teardown()
        self.assertRaises(UnusableStateError, consul_lock.acquire)


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
