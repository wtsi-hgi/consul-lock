import unittest
from typing import Callable, List, Dict, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration
from consullock.exceptions import InvalidKeyError, DoubleSlashKeyError
from consullock.locks import ConsulLock
from consullock.models import ConsulLockInformation
from consullock.tests._common import all_capture_builder
from consullock.tests._test_locks import BaseLockTest, DEFAULT_LOCK_INIT_ARGS_GENERATOR, DEFAULT_LOCK_INIT_KWARGS_GENERATOR, \
    LockerCallable, lock_when_unlocked, ConsulLockTestTimeoutError, lock_when_locked, DEFAULT_LOCK_ACQUIRE_TIMEOUT, \
    lock_twice, MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR, DOUBLE_SLASH_KEY


class TestConsulLock(BaseLockTest):
    """
    Tests for `ConsulLock`.
    """
    @staticmethod
    def _create_locker(
            lock_init_args: Callable[[str, ConsulDockerisedService], List]=DEFAULT_LOCK_INIT_ARGS_GENERATOR,
            lock_init_kwargs: Callable[[str, ConsulDockerisedService], Dict]=DEFAULT_LOCK_INIT_KWARGS_GENERATOR,
            acquire_args: List[Any]=None, acquire_kwargs: Dict[str, Any]=None) -> LockerCallable:
        def _locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
            nonlocal acquire_args, acquire_kwargs
            consul_lock = ConsulLock(*lock_init_args(key, service), **lock_init_kwargs(key, service))
            acquire_args = acquire_args if acquire_args is not None else []
            acquire_kwargs = acquire_kwargs if acquire_kwargs is not None else {}
            return all_capture_builder.build(consul_lock.acquire)(*acquire_args, **acquire_kwargs)
        return _locker

    @staticmethod
    def _unlocker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        consul_lock = ConsulLock(key, consul_client=service.create_consul_client())
        return all_capture_builder.build(consul_lock.release)()

    def test_lock_when_unlocked(self):
        lock_result, unlock_result = lock_when_unlocked(TestConsulLock._create_locker(), TestConsulLock._unlocker)
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)
        self.assertTrue(unlock_result.return_value)

    def test_lock_when_locked_blocking(self):
        lock_result = lock_when_locked(TestConsulLock._create_locker())
        self.assertIsInstance(lock_result.exception, ConsulLockTestTimeoutError)

    def test_lock_when_locked_non_blocking(self):
        lock_result = lock_when_locked(TestConsulLock._create_locker(acquire_kwargs=dict(blocking=False)))
        self.assertIsNone(lock_result.return_value)

    def test_lock_when_locked_with_timeout(self):
        lock_result = lock_when_locked(TestConsulLock._create_locker(
            acquire_kwargs=dict(timeout=DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2)))
        self.assertIsNone(lock_result.return_value)

    def test_set_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert isinstance(lock_result.return_value, ConsulLockInformation)

        _, lock_result = lock_twice(
            TestConsulLock._create_locker(lock_init_kwargs=lambda key, service: dict(
                **DEFAULT_LOCK_INIT_KWARGS_GENERATOR(key, service),
                session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS)),
            TestConsulLock._create_locker(),
            MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR,
            first_lock_callback
        )
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)

    def test_lock_with_double_slash(self):
        self.assertRaises(DoubleSlashKeyError, ConsulLock, DOUBLE_SLASH_KEY, consul_configuration=ConsulConfiguration(""))


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
