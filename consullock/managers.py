import atexit
import json
from datetime import datetime
from threading import Lock
from time import sleep
from typing import Callable, Optional, Any, Set, List

import requests
from consul import Consul
from consul.base import ACLPermissionDenied, ConsulException
from requests import Session
from timeout_decorator import timeout_decorator

from consullock._helpers import create_consul_client
from consullock._logging import create_logger
from consullock.configuration import DEFAULT_LOCK_POLL_INTERVAL_GENERATOR, MIN_LOCK_TIMEOUT_IN_SECONDS, \
    MAX_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration
from consullock.exceptions import ConsulLockBaseError, LockAcquireTimeoutError, UnusableStateError, \
    ConsulConnectionError, PermissionDeniedConsulError, SessionLostConsulError, InvalidKeyError, DoubleSlashKeyError, \
    InvalidSessionTtlValueError
from consullock.json_mappers import ConsulLockInformationJSONEncoder, ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation

logger = create_logger(__name__)


def _exception_converter(callable: Callable) -> Callable:
    """
    Decorator that converts exceptions from underlying libraries to native exceptions.
    :param callable: the callable to convert exceptions of
    :return: wrapped callable
    """
    def wrapped(*args, **kwargs) -> Any:
        try:
            return callable(*args, **kwargs)
        except ConsulLockBaseError as e:
            raise e
        except ACLPermissionDenied as e:
            raise PermissionDeniedConsulError() from e
        except Exception as e:
            raise ConsulConnectionError() from e
    return wrapped


def _raise_if_teardown_called(callable: Callable) -> Callable:
    """
    Decorator that raises an exception if consul lock manager has been torn down.
    :param callable: the callable to wrap (where `ConsulLock` is always passed as the first argument)
    :return: wrapped callable
    """
    def wrapper(consul_lock: "ConsulLockManager", *args, **kwargs):
        if consul_lock._teardown_called:
            raise UnusableStateError("Teardown has been called on the lock manager")
        return callable(consul_lock, *args, **kwargs)
    return wrapper


class ConsulLockManager:
    """
    TODO
    """
    @staticmethod
    def validate_session_ttl(session_timeout_in_seconds: float):
        """
        Validates the given session timeout, raising a `ValueError` if it is invalid.
        :param session_timeout_in_seconds: the timeout to validate
        :raises InvalidSessionTtlValueError: if the timeout is invalid
        """
        if session_timeout_in_seconds < MIN_LOCK_TIMEOUT_IN_SECONDS \
                or session_timeout_in_seconds > MAX_LOCK_TIMEOUT_IN_SECONDS:
            raise InvalidSessionTtlValueError(
                f"Invalid session timeout: {session_timeout_in_seconds}. If defined, the timeout must be between "
                f"{MIN_LOCK_TIMEOUT_IN_SECONDS} and {MAX_LOCK_TIMEOUT_IN_SECONDS} (inclusive).")

    @staticmethod
    def validate_key(key: str):
        """
        TODO
        :param key:
        :return:
        :raises InvalidKeyError:
        """
        if "//" in key:
            raise DoubleSlashKeyError(key)

    def __init__(self, *, consul_configuration: ConsulConfiguration=None, session_ttl_in_seconds: float=None,
                 lock_poll_interval_generator: Callable[[], float]=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR,
                 consul_client: Consul=None, regex_key: bool=False):
        """
        TODO
        :param consul_configuration:
        :param session_ttl_in_seconds:
        :param lock_poll_interval_generator:
        :param consul_client:
        :param regex_key:
        :raises InvalidSessionTtlValueError: if the `session_ttl_in_seconds` is not valid
        """
        if session_ttl_in_seconds is not None:
            ConsulLockManager.validate_session_ttl(session_ttl_in_seconds)
        if consul_configuration is not None and consul_client is not None:
            raise ValueError("Must either define `consul_configuration` or `consul_client`, not both")
        if consul_configuration is None and consul_client is None:
            raise ValueError("Either `consul_configuration` xor `consul_client` must be given")

        self.consul_client = consul_client or create_consul_client(consul_configuration)
        self.session_ttl_in_seconds = session_ttl_in_seconds
        self.lock_poll_interval_generator = lock_poll_interval_generator
        self._acquiring_session_ids: Set[Session] = set()

        # Try to stop any zombie sessions if premature exit
        atexit.register(self.teardown)
        self._teardown_called = False
        self._teardown_lock = Lock()

    @_exception_converter
    @_raise_if_teardown_called
    def acquire(self, key: str, blocking: bool=True, timeout: float=None) -> Optional[ConsulLockInformation]:
        """
        TODO
        :param key:
        :param blocking:
        :param timeout: timeout in seconds
        :return:
        :raises InvalidKeyError: if the `key` is not valid
        """
        ConsulLockManager.validate_key(key)

        session_id = self.consul_client.session.create(
            lock_delay=0, ttl=self.session_ttl_in_seconds, behavior="delete")
        self._acquiring_session_ids.add(session_id)
        logger.info(f"Created session with ID: {session_id}")

        @timeout_decorator.timeout(timeout, timeout_exception=LockAcquireTimeoutError)
        def _acquire() -> ConsulLockInformation:
            while True:
                logger.debug("Going to acquire lock")
                lock_information = self._acquire_lock(key, session_id)
                if lock_information is not None or not blocking:
                    logger.debug("Acquired lock!")
                    return lock_information
                else:
                    logger.debug("Could not acquire lock (already locked)")
                interval = self.lock_poll_interval_generator()
                logger.debug(f"Sleeping for {interval}s")
                sleep(interval)

        lock_information = _acquire()
        if lock_information is None:
            self.consul_client.session.destroy(session_id=session_id)
            self._acquiring_session_ids.remove(session_id)
            logger.info(f"Destroyed session (did not acquire the lock)")

        return lock_information

    @_exception_converter
    @_raise_if_teardown_called
    def release(self, key: str) -> bool:
        """
        Release the lock.

        Noop if not locked.
        :param key: TODO
        :return: whether a lock has been released
        :raises InvalidKeyError: if the `key` is not valid
        """
        ConsulLockManager.validate_key(key)

        key_value = self.consul_client.kv.get(key)[1]
        if key_value is None:
            logger.info(f"No lock found")
            return False

        lock_information = json.loads(key_value["Value"].decode("utf-8"), cls=ConsulLockInformationJSONDecoder)
        logger.info(f"Destroying the session {lock_information.session_id} that is holding the lock")
        unlocked = self.consul_client.session.destroy(session_id=lock_information.session_id)
        # This instance might be managing the removed session
        try:
            self._acquiring_session_ids.remove(lock_information.session_id)
        except KeyError:
            pass

        logger.info("Unlocked" if unlocked else "Went to unlock but was already released upon sending request")
        return unlocked

    @_exception_converter
    @_raise_if_teardown_called
    def release_all(self, keys: List[str]) -> List[bool]:
        """
        Releases all of the given keys.
        :param keys: the keys to release
        :return: whether the keys were released
        """
        released: List[bool] = []
        for key in keys:
            released.append(self.release(key))
        return released

    @_exception_converter
    @_raise_if_teardown_called
    def find(self, name_regex: str):
        """
        TODO
        :param name_regex:
        :return:
        """

    @_exception_converter
    def teardown(self):
        """
        Tears down the instance, removing any remaining sessions that this instance has created.

        The instance must not be used after this method has been called.
        """
        with self._teardown_lock:
            if not self._teardown_called:
                self._teardown_called = True
                logger.info(f"Destroying all sessions that have not acquired keys: {self._acquiring_session_ids}...")
                for session_id in self._acquiring_session_ids:
                    try:
                        self.consul_client.session.destroy(session_id=session_id)
                        logger.debug(f"Destroyed: {session_id}")
                    except requests.exceptions.ConnectionError as e:
                        logger.debug(e)
                        logger.warning(f"Could not connect to Consul to clean up session {session_id}")
                atexit.unregister(self.teardown)

    def _acquire_lock(self, key: str, session_id: str) -> Optional[ConsulLockInformation]:
        """
        Attempts to get the lock using the given session.
        :param key: TODO
        :param session_id: the identifier of the Consul session that should try to hold the lock
        :return: details about the lock if acquired, else `None`
        :raises SessionLostConsulError: if the Consul session is lost
        """
        lock_information = ConsulLockInformation(session_id, datetime.utcnow())
        value = json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, indent=4, sort_keys=True)
        try:
            success = self.consul_client.kv.put(key=key, value=value, acquire=session_id)
        except ConsulException as e:
            if "invalid session" in e.args[0]:
                raise SessionLostConsulError() from e
            raise e
        return lock_information if success else None


