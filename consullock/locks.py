import json
import logging
from datetime import datetime
from time import sleep
from typing import Callable, Optional

from consul import Consul
from timeout_decorator import timeout_decorator

from consullock._logging import create_logger
from consullock.exceptions import ConsulLockAcquireTimeout
from consullock.json_mappers import ConsulLockInformationJSONEncoder, ConsulLockInformationJSONDecoder
from consullock.model import ConsulLockInformation

from consul.base import ACLPermissionDenied

DEFAULT_LOCK_POLL_INTERVAL_GENERATOR = lambda: 5.0

MIN_LOCK_TIMEOUT_IN_SECONDS = 10
MAX_LOCK_TIMEOUT_IN_SECONDS = 86400

logger = create_logger(__name__)


class PermissionDeniedError(Exception):
    """
    TODO
    """


def _exception_converter(callable: Callable) -> Callable:
    """
    TODO
    :param callable:
    :return:
    """
    def wrapped(args, *kwargs):
        try:
            callable(args, *kwargs)
        except ACLPermissionDenied as e:
            raise PermissionDeniedError() from e
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
        TODO
        :param key:
        :param consul_client:
        :param lock_ttl_in_seconds:
        :param lock_poll_period_in_seconds:
        """

        if session_ttl_in_seconds is not None:
            ConsulLock.validate_session_ttl(session_ttl_in_seconds)

        self.key = key
        self.consul_client = consul_client
        self._session_ttl_in_seconds = session_ttl_in_seconds
        self.lock_poll_interval_generator = lock_poll_interval_generator

    @_exception_converter
    def acquire(self, blocking: bool=True, timeout: int=None) -> Optional[str]:
        """
        TODO
        :param blocking:
        :param timeout:
        :return:
        """
        session_id = self.consul_client.session.create(
            lock_delay=0, ttl=self._session_ttl_in_seconds, behavior="delete")
        logger.info(f"Created session with ID: {session_id}")

        @timeout_decorator.timeout(timeout, timeout_exception=ConsulLockAcquireTimeout)
        def _acquire():
            while True:
                success = self._acquire_consul_key(session_id)
                if success:
                    return True
                elif not blocking:
                    return False
                interval = self.lock_poll_interval_generator()
                sleep(interval)

        try:
            return session_id if _acquire() else None
        except ConsulLockAcquireTimeout:
            return None

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
        unlocked = self.consul_client.session.destroy(session_id=lock_information.session_id)

        logger.info("Unlocked" if unlocked else "Went to unlock but was already released upon sending request")
        return unlocked



    @_exception_converter
    def _acquire_consul_key(self, session_id: str):
        """
        TODO
        :param session_id:
        :return:
        """
        lock_information = ConsulLockInformation(session_id, datetime.utcnow())
        value = json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, indent=4, sort_keys=True)
        logger.debug(f"Key value {value}")
        return self.consul_client.kv.put(key=self.key, value=value, acquire=session_id)
