import os
import unittest
from abc import abstractmethod, ABCMeta
from copy import deepcopy
from typing import Callable, Tuple, Any

from capturewrap import CaptureResult
from timeout_decorator import timeout_decorator
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS
from consullock.locks import ConsulLock
from consullock.exceptions import ConsulLockBaseError
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY

LockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]
UnlockerCallable = Callable[[str, ConsulDockerisedService], CaptureResult]

DEFAULT_LOCK_INIT_ARGS_GENERATOR = lambda key, service: [key]
DEFAULT_LOCK_INIT_KWARGS_GENERATOR = lambda key, service: dict(consul_client=service.create_consul_client())
DEFAULT_LOCK_ACQUIRE_TIMEOUT = 0.5

MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR = MIN_LOCK_TIMEOUT_IN_SECONDS * 5.0
DOUBLE_SLASH_KEY = "my//key"


def lock_when_unlocked(locker: LockerCallable, unlocker: UnlockerCallable, key: str=TEST_KEY) \
        -> Tuple[CaptureResult, CaptureResult]:
    """
    Tests getting a lock when it is not locked.
    :param locker: method that locks Consul
    :param unlocker: method that unlocks Consul
    :param key: lock key to use
    :return: tuple where the first element is the result of the lock and the second is that of a subsequent unlock
    """
    with ConsulServiceController().start_service() as service:
        lock_result = locker(key, service)
        unlock_result = unlocker(key, service)
        return lock_result, unlock_result


def lock_twice(first_locker: LockerCallable, second_locker: LockerCallable,
               max_second_lock_wait: float=DEFAULT_LOCK_ACQUIRE_TIMEOUT,
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


def lock_when_locked(locker: LockerCallable, max_lock_block: float=DEFAULT_LOCK_ACQUIRE_TIMEOUT) -> CaptureResult:
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


class ConsulLockTestTimeoutError(ConsulLockBaseError):
    """
    Raised when a timeout occurs in a test.
    """


class BaseLockTest(unittest.TestCase, metaclass=ABCMeta):
    """
    TODO
    """
    def setUp(self):
        self._consul_service_controller = ConsulServiceController()
        self._env_cache = deepcopy(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_cache)

    @abstractmethod
    def test_lock_when_unlocked(self):
        """
        TODO
        """

    @abstractmethod
    def test_lock_when_locked_blocking(self):
        """
        TODO
        """

    @abstractmethod
    def test_lock_when_locked_non_blocking(self):
        """
        TODO
        """

    @abstractmethod
    def test_lock_when_locked_with_timeout(self):
        """
        TODO
        """

    @abstractmethod
    def test_set_session_ttl(self):
        """
        TODO
        """

    @abstractmethod
    def test_lock_with_double_slash(self):
        """
        TODO
        :return:
        """
