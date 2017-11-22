import unittest
from typing import Callable, Any, Tuple, Optional, List, Dict
from unittest import TestCase

from capturewrap import CaptureResult, CaptureWrapBuilder
from timeout_decorator import timeout_decorator

from consullock.locks import ConsulLock
from consullock.models import ConsulLockInformation
from consullock.tests._common import _EnvironmentPreservingTest, set_consul_env, TEST_KEY, all_capture_builder
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

LockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]
UnlockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]


def lock_when_unlocked(test: TestCase, locker: LockerCallable, unlocker: UnlockerCallable) \
        -> Tuple[CaptureResult, CaptureResult]:
    """
    TODO
    :param test:
    :param locker:
    :param unlocker:
    :return: tuple where the first element is the result of the lock and the second is that of a subsequent unlock
    """
    with ConsulServiceController().start_service() as service:
        set_consul_env(service)
        lock_result = locker(TEST_KEY, service)
        unlock_result = unlocker(TEST_KEY, service)
        return lock_result, unlock_result


def test_lock_when_locked(test: TestCase, locker: LockerCallable):
    """
    TODO
    :param test:
    :param locker:
    :return:
    """
    with ConsulServiceController().start_service() as service:
        consul_lock = ConsulLock(TEST_KEY, consul_client=service.create_consul_client())
        assert consul_lock.acquire(TEST_KEY)

        set_consul_env(service)

        @timeout_decorator.timeout(0.5)
        def get_lock_with_timeout():
            result = locker(TEST_KEY, service)
            if isinstance(result.exception, timeout_decorator.TimeoutError):
                raise result.exception

        try:
            test.assertRaises(timeout_decorator.TimeoutError, get_lock_with_timeout)
        finally:
            consul_lock.teardown()


class TestConsulLock(_EnvironmentPreservingTest):
    """
    Tests for ConsulLock.
    """
    @staticmethod
    def _create_locker(
            generate_args: Callable[[str, ConsulDockerisedService], List]=lambda key, service: [key],
            generate_kwargs: Callable[[str, ConsulDockerisedService], Dict]=
            lambda key, service: dict(consul_client=service.create_consul_client())) -> LockerCallable:
        def _locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
            consul_lock = ConsulLock(*generate_args(key, service), **generate_kwargs(key, service))
            return all_capture_builder.build(consul_lock.acquire)()
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


if __name__ == "__main__":
    unittest.main()
