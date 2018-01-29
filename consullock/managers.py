import atexit
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from io import TextIOWrapper, StringIO
from json import JSONDecodeError
from os.path import normpath
from threading import Lock
from time import sleep, monotonic

from munch import Munch
from types import SimpleNamespace
from typing import Callable, Optional, Any, Set, List, Dict, Sequence, Tuple

import requests
from consul import Consul
from consul.base import ACLPermissionDenied, ConsulException
from requests import Session
from timeout_decorator import timeout_decorator

from consullock._helpers import create_consul_client
from consullock._logging import create_logger
from consullock.configuration import DEFAULT_LOCK_POLL_INTERVAL_GENERATOR, MIN_LOCK_TIMEOUT_IN_SECONDS, \
    MAX_LOCK_TIMEOUT_IN_SECONDS, ConsulConfiguration, get_consul_configuration_from_environment
from consullock.exceptions import ConsulLockBaseError, LockAcquireTimeoutError, UnusableStateError, \
    ConsulConnectionError, PermissionDeniedConsulError, SessionLostConsulError, DoubleSlashKeyError, \
    InvalidSessionTtlValueError, NonNormalisedKeyError
from consullock.json_mappers import ConsulLockInformationJSONEncoder, ConsulLockInformationJSONDecoder
from consullock.models import ConsulLockInformation, ConnectedConsulLockInformation

KEY_DIRECTORY_SEPARATOR = "/"
LockEventListener = Callable[[str], None]

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
        except ConsulException as e:
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
    Manager of Consul locks.
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
        Validates the given key.
        :param key: the key to validate
        :raises InvalidKeyError: raised if the given key is invalid
        """
        if "//" in key:
            raise DoubleSlashKeyError(key)
        elif normpath(key) != key:
            raise NonNormalisedKeyError(key)

    def __init__(self, *, consul_configuration: ConsulConfiguration=None, session_ttl_in_seconds: float=None,
                 consul_client: Consul=None):
        """
        Constructor.
        :param consul_configuration: configuration used to connect to Consul (required if `consul_client` is not given)
        :param session_ttl_in_seconds: the TTL of Consul sessions
        :param consul_client: client used to connect to Consul (required if `consul_configuration` is not given)
        :raises InvalidSessionTtlValueError: if the `session_ttl_in_seconds` is not valid
        """
        if session_ttl_in_seconds is not None:
            ConsulLockManager.validate_session_ttl(session_ttl_in_seconds)
        if consul_configuration is not None and consul_client is not None:
            raise ValueError("Must either define `consul_configuration` or `consul_client`, not both")
        if consul_configuration is None and consul_client is None:
            try:
                consul_configuration = get_consul_configuration_from_environment()
                logger.info("Gather Consul configuration from the environment")
                logger.debug(f"Consul configuration: {consul_configuration}")
            except KeyError:
                raise ValueError(
                    "Either `consul_configuration` xor `consul_client` must be given or the configuration to connect "
                    "to Consul must be in the environment")

        self.consul_client = consul_client or create_consul_client(consul_configuration)
        logger.debug(f"Consul configuration: {consul_configuration}")
        self.session_ttl_in_seconds = session_ttl_in_seconds
        self._acquiring_session_ids: Set[Session] = set()

        # Try to stop any zombie sessions if premature exit
        atexit.register(self.teardown)
        self._teardown_called = False
        self._teardown_lock = Lock()

    @_exception_converter
    @_raise_if_teardown_called
    def acquire(self, key: str, blocking: bool=True, timeout: float=None, metadata: Any=None,
                on_before_lock: LockEventListener=lambda key: None,
                on_lock_already_locked: LockEventListener=lambda key: None,
                lock_poll_interval_generator: Callable[[int], float]=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR) \
            -> Optional[ConnectedConsulLockInformation]:
        """
        Acquires a Consul lock.
        :param key: the lock key
        :param blocking: whether to block and wait for the lock
        :param timeout: timeout in seconds
        :param metadata: metadata to add to the lock information. Must be parsable by default JSON encode/decoder
        :param on_before_lock: event listener to be called before attempt to acquire lock
        :param on_lock_already_locked: event listener to be called when an attempt to acquire a lock has failed as the
        lock is already locked
        :param lock_poll_interval_generator: generator of the interval between Consul lock polls where the first
        argument is the attempt number (starting at 1)
        :return: information about the lock if acquired, else `None` if not acquired and not blocking
        :raises InvalidKeyError: raised if the given key is not valid
        :raises LockAcquireTimeoutError: raised if times out waiting for the lock
        """
        ConsulLockManager.validate_key(key)

        logger.debug("Creating Consul session...")
        session_id = self.consul_client.session.create(
            lock_delay=0, ttl=self.session_ttl_in_seconds, behavior="delete")
        self._acquiring_session_ids.add(session_id)
        logger.info(f"Created session with ID: {session_id}")
        start_time = monotonic()

        @timeout_decorator.timeout(timeout, timeout_exception=LockAcquireTimeoutError)
        def _acquire() -> Optional[ConsulLockInformation]:
            i = 1
            while True:
                logger.debug("Going to acquire lock")
                seconds_to_lock = monotonic() - start_time
                on_before_lock(key)
                lock_information = self._acquire_lock(key, session_id, seconds_to_lock, metadata)
                if lock_information is not None:
                    logger.debug("Acquired lock!")
                    return lock_information
                else:
                    on_lock_already_locked(key)
                    if not blocking:
                        logger.debug("Could not acquire lock (already locked) and not blocking")
                        return None
                    else:
                        logger.debug("Could not acquire lock (already locked)")
                interval = lock_poll_interval_generator(i)
                logger.debug(f"Sleeping for {interval}s")
                sleep(interval)
                i += 1

        lock_information = _acquire()
        self._acquiring_session_ids.remove(session_id)

        if lock_information is None:
            self.consul_client.session.destroy(session_id=session_id)
            logger.info(f"Destroyed session (did not acquire the lock)")

        return lock_information

    @_exception_converter
    @_raise_if_teardown_called
    def execute(self, key: str, executable: str, *, capture_stdout: bool=False, capture_stderr: bool=False,
                **acquire_kwargs) -> Tuple[Optional[int], Optional[bytes], Optional[bytes]]:
        """
        Executes the given executable whilst holding the given lock.
        :param key:
        :param executable:
        :param capture_stdout:
        :param capture_stderr:
        :param acquire_kwargs:
        :return:
        """
        lock = self.acquire(key, **acquire_kwargs)
        if lock is None:
            return None, None, None
        return self.execute_with_lock(executable, lock, capture_stdout=capture_stdout, capture_stderr=capture_stderr)

    @_exception_converter
    @_raise_if_teardown_called
    def execute_with_lock(self, executable: str, lock: ConnectedConsulLockInformation, *, capture_stdout: bool=False,
                          capture_stderr: bool=False) -> Tuple[int, Optional[bytes], Optional[bytes]]:
        """
        TODO
        :param executable:
        :param lock:
        :param capture_stdout:
        :param capture_stderr:
        :return:
        """
        assert lock is not None
        redirects = Munch(stdout=subprocess.PIPE if capture_stdout else sys.stdout,
                         stderr=subprocess.PIPE if capture_stderr else sys.stderr)

        # Patch for when sys.stdout and sys.stderr have been reassigned (e.g. in IDE test runners)
        non_realtime_redirects: Dict[str, StringIO] = {}
        for name, redirect in redirects.items():
            if isinstance(redirect, StringIO):
                logger.warning(f"Cannot capture {name} in real-time as `sys.{name}` does not have a fileno")
                non_realtime_redirects[name] = redirect
                redirects[name] = subprocess.PIPE

        outputs = Munch(stdout=None, stderr=None)
        with lock:
            process = subprocess.Popen(executable, shell=True, stdout=redirects.stdout, stderr=redirects.stderr)
            outputs.stdout, outputs.stderr = process.communicate()

        # Second part of redirect reassignment patch
        for name, original_redirect in non_realtime_redirects.items():
            captured = outputs[name]
            getattr(sys, name).write(captured.decode("utf-8"))

        return process.returncode, \
               outputs.stdout if capture_stdout else None, \
               outputs.stderr if capture_stderr else None


    @_exception_converter
    @_raise_if_teardown_called
    def release(self, key: str) -> Optional[str]:
        """
        Release the lock.

        Noop if not locked.
        :param key: the name of the lock to release
        :return: the name of the released lock, or `None` if no lock was released
        :raises InvalidKeyError: if the `key` is not valid
        """
        ConsulLockManager.validate_key(key)

        key_value = self.consul_client.kv.get(key)[1]
        if key_value is None:
            logger.info(f"No lock found")
            return None

        lock_information = json.loads(key_value["Value"].decode("utf-8"), cls=ConsulLockInformationJSONDecoder)
        logger.info(f"Destroying the session {lock_information.session_id} that is holding the lock")
        unlocked = self.consul_client.session.destroy(session_id=lock_information.session_id)
        # This instance might be managing the removed session
        try:
            self._acquiring_session_ids.remove(lock_information.session_id)
        except KeyError:
            pass

        logger.info("Unlocked" if unlocked else "Went to unlock but was already released upon sending request")
        return key

    @_exception_converter
    @_raise_if_teardown_called
    def release_regex(self, key_regex: str) -> Set[str]:
        """
        Releases all locks with names that that match the given regular expression.
        :param key_regex: Python regular expression that captures the names of the locks that are to be released
        :return: the names of the locks that were released
        """
        keys = list(self.find_regex(key_regex).keys())
        return self.release_all(keys)

    @_exception_converter
    @_raise_if_teardown_called
    def release_all(self, keys: Sequence[str]) -> Set[str]:
        """
        Releases all of the given keys.
        :param keys: the keys to release
        :return: the names of the keys that were released
        """
        released: List[str] = []
        for key in keys:
            released.append(self.release(key))
        return set(filter(None,released))

    @_exception_converter
    @_raise_if_teardown_called
    def find(self, name: str) -> Optional[ConnectedConsulLockInformation]:
        """
        Finds the lock with the key name that matches that given.
        :param name: the lock key to match
        :return: the found lock
        """
        lock = self.consul_client.kv.get(name)[1]
        if lock is None:
            return None

        lock_information = json.loads(lock["Value"], cls=ConsulLockInformationJSONDecoder)
        return ConnectedConsulLockInformation(
            self, lock_information.key, lock_information.session_id, lock_information.created,
            lock_information.seconds_to_lock, lock_information.metadata)


    @_exception_converter
    @_raise_if_teardown_called
    def find_regex(self, name_regex: str) -> Dict[str, Optional[ConnectedConsulLockInformation]]:
        """
        Finds the locks with key names that match the given regex.
        :param name_regex: key name regex
        :return: keys that match
        """
        # Gets prefix directory (must not include regex!)
        escaped_name_regex = re.escape(name_regex)
        directory_prefix = os.path.commonprefix(
            (name_regex.replace(KEY_DIRECTORY_SEPARATOR, re.escape(KEY_DIRECTORY_SEPARATOR)), escaped_name_regex)) \
            .replace("\\", "")

        data = self.consul_client.kv.get(directory_prefix, recurse=True)[1]
        if data is None:
            return dict()
        key_indexed_data = {key_data["Key"]: key_data for key_data in data}

        name_pattern = re.compile(name_regex)
        matches = [value for key, value in key_indexed_data.items() if name_pattern.fullmatch(key) is not None]
        matched_return: Dict[str, Optional[ConsulLockInformation]] = dict()
        for match in matches:
            try:
                decoded_match = json.loads(match["Value"], cls=ConsulLockInformationJSONDecoder)
                matched_return[decoded_match.key] = decoded_match
            except JSONDecodeError:
                matched_return[match["Key"]] = None
        return matched_return

    @_exception_converter
    def teardown(self):
        """
        Tears down the instance, removing any remaining sessions that this instance has created.

        The instance must not be used after this method has been called.
        """
        with self._teardown_lock:
            if not self._teardown_called:
                self._teardown_called = True
                if len(self._acquiring_session_ids) > 0:
                    logger.info(
                        f"Destroying all sessions that have not acquired keys: {self._acquiring_session_ids}...")
                for session_id in self._acquiring_session_ids:
                    try:
                        self.consul_client.session.destroy(session_id=session_id)
                        logger.debug(f"Destroyed: {session_id}")
                    except requests.exceptions.ConnectionError as e:
                        logger.debug(f"Exception: {e}")
                        logger.warning(f"Could not connect to Consul to clean up session {session_id}")
                atexit.unregister(self.teardown)

    def _acquire_lock(self, key: str, session_id: str, seconds_to_lock: float, metadata: Any) \
            -> Optional[ConnectedConsulLockInformation]:
        """
        Attempts to get the lock using the given session.
        :param key: name of the lock
        :param session_id: the identifier of the Consul session that should try to hold the lock
        :param seconds_to_lock: the number of seconds it took to acquire the lock
        :param metadata: metadata to add to the lock information
        :return: details about the lock if acquired, else `None`
        :raises SessionLostConsulError: if the Consul session is lost
        """
        lock_information = ConnectedConsulLockInformation(
            self, key, session_id, datetime.utcnow(), seconds_to_lock, metadata)
        value = json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, indent=4, sort_keys=True)
        logger.debug(f"Attempting to acquire lock with value: {value}")
        try:
            success = self.consul_client.kv.put(key=key, value=value, acquire=session_id)
        except ConsulException as e:
            if "invalid session" in e.args[0]:
                raise SessionLostConsulError() from e
            raise e
        return lock_information if success else None
