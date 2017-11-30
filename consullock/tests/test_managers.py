import unittest
from typing import Callable, List, Dict, Any

from capturewrap import CaptureResult
from useintest.predefined.consul import ConsulDockerisedService, ConsulServiceController

from consullock.configuration import MIN_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration
from consullock.exceptions import DoubleSlashKeyError, InvalidSessionTtlValueError, UnusableStateError, \
    ConsulConnectionError
from consullock.managers import ConsulLockManager, KEY_DIRECTORY_SEPARATOR
from consullock.models import ConsulLockInformation
from consullock.tests._common import all_capture_builder, TEST_KEY, TEST_KEY_DIRECTORY, TEST_KEY_2
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
        self.assertIsNone(unlock_result.return_value)

    def test_unlock_when_locked(self):
        lock_result, unlock_result = double_action(
            TestConsulLockManager._create_locker(), TestConsulLockManager._unlocker)
        assert isinstance(lock_result.return_value, ConsulLockInformation)
        self.assertEqual(TEST_KEY, unlock_result.return_value)

    def test_unlock_all(self):
        test_keys = [f"{TEST_KEY}_{i}" for i in range(5)]
        with ConsulServiceController().start_service() as service:
            consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
            for key in test_keys:
                lock = consul_lock.acquire(key)
                assert isinstance(lock, ConsulLockInformation)
            unlock_results = consul_lock.release_all(test_keys)
        for unlock_result in unlock_results:
            self.assertTrue(unlock_result)

    def test_cannot_use_after_teardown(self):
        consul_lock = ConsulLockManager(consul_configuration=_DUMMY_CONSUL_CONFIGURATION)
        consul_lock.teardown()
        self.assertRaises(UnusableStateError, consul_lock.acquire)

    def test_find_when_no_locks(self):
        with ConsulServiceController().start_service() as service:
            consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
            found_locks = consul_lock.find(f"{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}[0-9]+")
            self.assertEqual(0, len(found_locks))

    def test_find_when_locks(self):
        interesting_keys = [f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}{i}"
                            for i in range(5)]
        other_keys = [TEST_KEY, f"other{TEST_KEY_DIRECTORY}", f"{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}1a", f"{TEST_KEY}0"]
        with ConsulServiceController().start_service() as service:
            consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
            for key in interesting_keys + other_keys:
                lock = consul_lock.acquire(key)
                assert isinstance(lock, ConsulLockInformation)
            found_locks = consul_lock.find(
                f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}[0-9]+")
            self.assertCountEqual(interesting_keys, [lock.key for lock in found_locks.values()])

    def test_find_when_locks_and_other_key(self):
        key_1 = f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}{TEST_KEY}"
        key_2 = f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}{TEST_KEY_2}"
        with ConsulServiceController().start_service() as service:
            consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
            test_lock = consul_lock.acquire(key_1)
            service.create_consul_client().kv.put(key_2, "unrelated")
            found_locks = consul_lock.find(f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}.*")
            self.assertEqual(2, len(found_locks))
            self.assertEqual(found_locks[key_1], test_lock)
            self.assertIsNone(found_locks[key_2])

    def test_unlock_with_regex(self):
        # with ConsulServiceController().start_service() as service:
        #     consul_lock = ConsulLockManager(consul_client=service.create_consul_client())
        pass


del BaseLockTest

if __name__ == "__main__":
    unittest.main()
