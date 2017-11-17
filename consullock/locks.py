import atexit
import json
from datetime import datetime
from time import sleep
from typing import Callable, Optional, Any

from consul import Consul
from consul.base import ACLPermissionDenied, ConsulException
from timeout_decorator import timeout_decorator

from consullock._logging import create_logger
from consullock.exceptions import ConsulLockAcquireTimeout
from consullock.json_mappers import ConsulLockInformationJSONEncoder, ConsulLockInformationJSONDecoder
from consullock.model import ConsulLockInformation

DEFAULT_LOCK_POLL_INTERVAL_GENERATOR = lambda: 1.0

MIN_LOCK_TIMEOUT_IN_SECONDS = 10
MAX_LOCK_TIMEOUT_IN_SECONDS = 86400

logger = create_logger(__name__)


class ConsulError(BaseException):
    """
    Wrapped exception from the underlying library dealing with Consul.
    """


class PermissionDeniedError(ConsulError):
    """
    Raised when Consul has refused to act due to a permission error.
    """


class SessionLostError(ConsulError):
    """
    Raised if a Consul session is lost in the middle of an operation.
    """


def _exception_converter(callable: Callable) -> Callable:
    """
    Converts exceptions from underlying libraries to native exceptions.
    :param callable: the callable to convert exceptions of
    :return: wrapped callable
    """
    def wrapped(*args, **kwargs) -> Any:
        try:
            return callable(*args, **kwargs)
        except ACLPermissionDenied as e:
            raise PermissionDeniedError() from e
        except ConsulException as e:
            if "invalid session" in e.args[0]:
                raise SessionLostError() from e
            else:
                raise ConsulError() from e
        except BaseException as e:
            raise e
        except Exception as e:
            raise ConsulError() from e
    return wrapped


class ConsulLock:
    """
    TODO
    """
    @staticmethod
    def validate_session_ttl(session_timeout_in_seconds: float):
        """
        Validates the given session timeout, raising a `ValueError` if it is invalid.
        :param session_timeout_in_seconds: the timeout to validate
        :raises ValueError: if the timeout is invalid
        """
        if session_timeout_in_seconds < MIN_LOCK_TIMEOUT_IN_SECONDS \
                or session_timeout_in_seconds > MAX_LOCK_TIMEOUT_IN_SECONDS:
            raise ValueError(
                f"Invalid session timeout: {session_timeout_in_seconds}. If defined, the timeout must be between "
                f"{MIN_LOCK_TIMEOUT_IN_SECONDS} and {MAX_LOCK_TIMEOUT_IN_SECONDS} (inclusive).")

    def __init__(self, key: str, consul_client: Consul, session_ttl_in_seconds: float=None,
                 lock_poll_interval_generator: Callable[[], float]=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR):
        """
        Constructor.
        :param key: lock key
        :param consul_client:
        :param session_ttl_in_seconds:
        :param lock_poll_interval_generator:
        """
        if session_ttl_in_seconds is not None:
            ConsulLock.validate_session_ttl(session_ttl_in_seconds)

        self.key = key
        self.consul_client = consul_client
        self._session_ttl_in_seconds = session_ttl_in_seconds
        self.lock_poll_interval_generator = lock_poll_interval_generator

    @_exception_converter
    def acquire(self, blocking: bool=True, timeout: float=None) -> Optional[ConsulLockInformation]:
        """
        TODO
        :param blocking:
        :param timeout: timeout in seconds
        :return:
        """
        session_id = self.consul_client.session.create(
            lock_delay=0, ttl=self._session_ttl_in_seconds, behavior="delete")
        logger.info(f"Created session with ID: {session_id}")

        def _destroy_session():
            logger.debug(f"Destroying session...")
            self.consul_client.session.destroy(session_id=session_id)
            logger.info(f"Destroyed session")

        # Try to stop zombie session when premature exit
        atexit.register(_destroy_session)

        @timeout_decorator.timeout(timeout, timeout_exception=ConsulLockAcquireTimeout)
        def _acquire() -> ConsulLockInformation:
            while True:
                logger.debug("Going to acquire lock")
                lock_information = self._acquire_consul_key(session_id)
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
            _destroy_session()
        atexit.unregister(_destroy_session)
        return lock_information


    @_exception_converter
    def release(self) -> bool:
        """
        Release the lock.

        Noop if not locked.
        :return: whether a lock has been released
        """
        key_value = self.consul_client.kv.get(self.key)[1]
        if key_value is None:
            logger.info(f"No lock found")
            return False

        lock_information = json.loads(key_value["Value"].decode("utf-8"), cls=ConsulLockInformationJSONDecoder)
        logger.info(f"Destroying the session {lock_information.session_id} that is holding the lock")
        unlocked = self.consul_client.session.destroy(session_id=lock_information.session_id)

        logger.info("Unlocked" if unlocked else "Went to unlock but was already released upon sending request")
        return unlocked

    @_exception_converter
    def _acquire_consul_key(self, session_id: str) -> ConsulLockInformation:
        """
        TODO
        :param session_id:
        :return:
        """
        lock_information = ConsulLockInformation(session_id, datetime.utcnow())
        value = json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, indent=4, sort_keys=True)
        success = self.consul_client.kv.put(key=self.key, value=value, acquire=session_id)
        return lock_information if success else None