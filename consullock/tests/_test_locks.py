import os
import unittest
from abc import abstractmethod, ABCMeta
from copy import deepcopy
from typing import Callable, Tuple, Any, List

from capturewrap import CaptureResult
from timeout_decorator import timeout_decorator
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS
from consullock.managers import ConsulLockManager
from consullock.exceptions import ConsulLockBaseError
from consullock.models import ConsulLockInformation
from consullock.tests._common import TEST_KEY

LockActionCallable = Callable[[str, ConsulDockerisedService], CaptureResult]
LockerCallable = LockActionCallable
UnlockerCallable = LockActionCallable

DEFAULT_LOCK_ACQUIRE_TIMEOUT = 0.5

MAX_WAIT_TIME_FOR_MIN_TTL_SESSION_TO_CLEAR = MIN_LOCK_TIMEOUT_IN_SECONDS * 5.0
DOUBLE_SLASH_KEY = "my//key"


def acquire_locks(locker: LockerCallable, keys: List[str]=None,
                  on_complete: Callable[[ConsulDockerisedService], None]=None) -> List[CaptureResult]:
    """
    Test getting locks.
    :param locker: method that locks Consul
    :param keys: optional keys of the locks to acquire (in order). Will use single test key if not defined
    :param on_complete: optional method to call before the service is taken down
    :return: the result of the lock acquisitions
    """
    if keys is None:
        keys = [TEST_KEY]
    lock_results: List[CaptureResult] = []
    with ConsulServiceController().start_service() as service:
        for key in keys:
            lock_results.append(locker(key, service))
        if on_complete is not None:
            on_complete(service)
        return lock_results


def double_action(first_action: LockActionCallable, second_action: LockActionCallable,
                  second_action_timeout: float=DEFAULT_LOCK_ACQUIRE_TIMEOUT,
                  first_action_callback: Callable[[CaptureResult], Any]=None) -> Tuple[CaptureResult, CaptureResult]:
    """
    Do two consecutive actions.
    :param first_action: first action to execute
    :param second_action: second action to execute
    :param second_action_timeout: timeout in seconds of the second action
    :param first_action_callback: optional callback after first action that is given the result of the first action
    :return: tuple where the first value is the captured result of the first action and the second is the captured
    result of the second action
    :raises TestActionTimeoutError: raised if the second action times out
    """
    with ConsulServiceController().start_service() as service:
        first_action_result = first_action(TEST_KEY, service)
        if first_action_callback:
            first_action_callback(first_action_result)

        @timeout_decorator.timeout(second_action_timeout, timeout_exception=TestActionTimeoutError)
        def second_action_with_timeout() -> CaptureResult:
            return second_action(TEST_KEY, service)

        try:
            return first_action_result, second_action_with_timeout()
        except TestActionTimeoutError as e:
            return first_action_result, CaptureResult(exception=e)


def action_when_locked(action: LockActionCallable, timeout: float=DEFAULT_LOCK_ACQUIRE_TIMEOUT) -> CaptureResult:
    """
    Tests getting a lock when it is already locked.
    :param locker: method that locks Consul
    :param timeout: maximum amount of time (in seconds) to block for
    :raise timeout_decorator.TimeoutError: if block on lock times out
    """
    def first_locker(key: str, service: ConsulDockerisedService) -> CaptureResult:
        lock_manager = ConsulLockManager(consul_client=service.create_consul_client())
        lock_information = lock_manager.acquire(TEST_KEY)
        return CaptureResult(return_value=lock_information)

    def first_lock_callback(lock_result: CaptureResult):
        assert isinstance(lock_result.return_value, ConsulLockInformation)

    _, lock_result = double_action(first_locker, action, timeout, first_lock_callback)
    return lock_result


class TestActionTimeoutError(ConsulLockBaseError):
    """
    Raised when a timeout occurs in a test.
    """


class BaseLockTest(unittest.TestCase, metaclass=ABCMeta):
    """
    Base class for all interfaces that can be used to manage Consul locks.
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
        Tests that a lock can be acquired if not locked.
        """

    @abstractmethod
    def test_lock_when_locked_blocking(self):
        """
        Tests that a lock cannot be acquired if already locked and that the thread blocks on the call to acquire.
        """

    @abstractmethod
    def test_lock_when_locked_non_blocking(self):
        """
        Tests that a lock cannot be acquired if already locked and that the thread does not block on the call to
        acquire.
        """

    @abstractmethod
    def test_lock_when_locked_with_timeout(self):
        """
        Tests that a lock acquire can timeout.
        """

    @abstractmethod
    def test_lock_with_session_ttl(self):
        """
        Tests that a lock with a session TTL can be set.
        """

    @abstractmethod
    def test_lock_with_invalid_session_ttl(self):
        """
        Tests that a lock with an invalid session TTL cannot be set.
        """

    @abstractmethod
    def test_lock_with_double_slash(self):
        """
        Tests that a lock with a double slash (//) cannot be set.
        """

    @abstractmethod
    def test_unlock_when_unlocked(self):
        """
        Tests that a lock can be unlocked when not locked.
        """

    @abstractmethod
    def test_unlock_when_locked(self):
        """
        Tests that a lock can be unlocked when locked.
        """

    @abstractmethod
    def test_unlock_with_regex(self):
        """
        Test unlocking locks with a name matching a regular expression.
        """
