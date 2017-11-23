import unittest
from typing import Callable, Tuple, List, Dict, Any

from capturewrap import CaptureResult
from timeout_decorator import timeout_decorator
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS
from consullock.locks import ConsulLock, ConsulLockBaseError
from consullock.models import ConsulLockInformation
from consullock.tests._common import _EnvironmentPreservingTest, TEST_KEY, all_capture_builder

LockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]
UnlockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]

DEFAULT_LOCK_INIT_ARGS_GENERATOR = lambda key, service: [key]
DEFAULT_LOCK_INIT_KWARGS_GENERATOR = lambda key, service: dict(consul_client=service.create_consul_client())
_DEFAULT_LOCK_ACQUIRE_TIMEOUT = 0.5


class ConsulLockTestTimeoutError(ConsulLockBaseError):
    """
    Raised when a timeout occurs in a test.
    """

def lock_when_unlocked(locker: LockerCallable, unlocker: UnlockerCallable) \
        -> Tuple[CaptureResult, CaptureResult]:
    """
    Tests getting a lock when it is not locked.
    :param locker: method that locks Consul
    :param unlocker: method that unlocks Consul
    :return: tuple where the first element is the result of the lock and the second is that of a subsequent unlock
    """
    with ConsulServiceController().start_service() as service:
        lock_result = locker(TEST_KEY, service)
        unlock_result = unlocker(TEST_KEY, service)
        return lock_result, unlock_result


def lock_twice(first_locker: LockerCallable, second_locker: LockerCallable,
               max_second_lock_wait: float=_DEFAULT_LOCK_ACQUIRE_TIMEOUT,
               first_lock_callback: Callable[[CaptureResult], Any]=None) -> Tuple[CaptureResult, CaptureResult]:
    """
    TODO
    :param first_locker:
    :param second_locker:
    :param max_second_lock_wait:
    :return:
    """
    with ConsulServiceController().start_service() as service:
        first_lock_result = first_locker(TEST_KEY, service)
        if first_lock_callback:
            first_lock_callback(first_lock_result)

        @timeout_decorator.timeout(max_second_lock_wait, timeout_exception=ConsulLockTestTimeoutError)
        def get_lock_with_timeout() -> CaptureResult:
            return second_locker(TEST_KEY, service)

        try:
            return first_lock_result, get_lock_with_timeout()
        except ConsulLockTestTimeoutError as e:
            return first_lock_result, CaptureResult(exception=e)


def lock_when_locked(locker: LockerCallable, max_lock_block: float=_DEFAULT_LOCK_ACQUIRE_TIMEOUT) -> CaptureResult:
    """
    Tests getting a lock when it is already locked.
    :param locker: method that locks Consul
    :param unlocker: method that unlocks Consul
    :param max_lock_block: maximum amount of time (in seconds) to block for
    :raise timeout_decorator.TimeoutError: if block on lock times out
    """
    def first_locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        consul_lock = ConsulLock(TEST_KEY, consul_client=service.create_consul_client())
        lock_information = consul_lock.acquire()
        return CaptureResult(return_value=lock_information)

    def first_lock_callback(lock_result: CaptureResult):
        assert isinstance(lock_result.return_value, ConsulLockInformation)

    _, lock_result = lock_twice(first_locker, locker, max_lock_block, first_lock_callback)
    return lock_result


class TestConsulLock(_EnvironmentPreservingTest):
    """
    Tests for ConsulLock.
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
            acquire_kwargs=dict(timeout=_DEFAULT_LOCK_ACQUIRE_TIMEOUT / 2)))
        self.assertIsNone(lock_result.return_value)

    def test_set_session_ttl(self):
        def first_lock_callback(lock_result: CaptureResult):
            assert isinstance(lock_result.return_value, ConsulLockInformation)

        _, lock_result = lock_twice(
            TestConsulLock._create_locker(lock_init_kwargs=lambda key, service: dict(
                **DEFAULT_LOCK_INIT_KWARGS_GENERATOR(key, service),
                session_ttl_in_seconds=MIN_LOCK_TIMEOUT_IN_SECONDS)),
            TestConsulLock._create_locker(),
            MIN_LOCK_TIMEOUT_IN_SECONDS * 5.0,
            first_lock_callback
        )
        self.assertIsInstance(lock_result.return_value, ConsulLockInformation)


if __name__ == "__main__":
    unittest.main()
