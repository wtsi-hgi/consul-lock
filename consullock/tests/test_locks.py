import unittest
from typing import Callable, Tuple, List, Dict, Any
from unittest import TestCase

from capturewrap import CaptureResult
from timeout_decorator import timeout_decorator

from consullock.locks import ConsulLock
from consullock.models import ConsulLockInformation
from consullock.tests._common import _EnvironmentPreservingTest, set_consul_env, TEST_KEY, all_capture_builder
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

LockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]
UnlockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]

_DEFAULT_LOCK_INIT_ARGS_GENERATOR = lambda key, service: [key]
_DEFAULT_LOCK_INIT_KWARGS_GENERATOR = lambda key, service: dict(consul_client=service.create_consul_client())


def lock_when_unlocked(test: TestCase, locker: LockerCallable, unlocker: UnlockerCallable) \
        -> Tuple[CaptureResult, CaptureResult]:
    """
    Tests getting a lock when it is not locked.
    :param test: the test case running the test
    :param locker: method that locks Consul
    :param unlocker: method that unlocks Consul
    :return: tuple where the first element is the result of the lock and the second is that of a subsequent unlock
    """
    with ConsulServiceController().start_service() as service:
        lock_result = locker(TEST_KEY, service)
        unlock_result = unlocker(TEST_KEY, service)
        return lock_result, unlock_result


def test_lock_when_locked(test: TestCase, locker: LockerCallable):
    """
    Tests getting a lock when it is already locked.
    :param test: the test case running the test
    :param locker: method that locks Consul
    :param unlocker: method that unlocks Consul
    """
    with ConsulServiceController().start_service() as service:
        consul_lock = ConsulLock(TEST_KEY, consul_client=service.create_consul_client())
        assert consul_lock.acquire(TEST_KEY)

        @timeout_decorator.timeout(0.5)
        def get_lock_with_timeout():
            result = locker(TEST_KEY, service)
            if isinstance(result.exception, timeout_decorator.TimeoutError):
                raise result.exception

        try:
            test.assertRaises(timeout_decorator.TimeoutError, get_lock_with_timeout)
        finally:
            consul_lock.teardown()


def test_lock_with_blocking_when_locked(test: TestCase, locker: LockerCallable) -> CaptureResult:
    """
    TODO
    :param test:
    :param locker:
    :return:
    """
    with ConsulServiceController().start_service() as service:
        consul_lock = ConsulLock(TEST_KEY, consul_client=service.create_consul_client())
        assert consul_lock.acquire(TEST_KEY)
        return locker(TEST_KEY, service)


class TestConsulLock(_EnvironmentPreservingTest):
    """
    Tests for ConsulLock.
    """
    @staticmethod
    def _create_locker(
            lock_init_args: Callable[[str, ConsulDockerisedService], List]=_DEFAULT_LOCK_INIT_ARGS_GENERATOR,
            lock_init_kwargs: Callable[[str, ConsulDockerisedService], Dict]=_DEFAULT_LOCK_INIT_KWARGS_GENERATOR,
            acquire_args: List[Any]=None, acquire_kwargs: Dict[str, Any]=None) \
            -> LockerCallable:
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
        lock_result, unlock_result = lock_when_unlocked(self, TestConsulLock._create_locker(), TestConsulLock._unlocker)
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)
        self.assertTrue(unlock_result.return_value)

    def test_lock_when_locked(self):
        test_lock_when_locked(self, TestConsulLock._create_locker())

    def test_lock_when_locked_with_blocking(self):
        lock_result = test_lock_with_blocking_when_locked(
            self, TestConsulLock._create_locker(acquire_kwargs=dict(blocking=False)))
        self.assertIsNone(lock_result.return_value)


if __name__ == "__main__":
    unittest.main()
