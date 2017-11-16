import logging
from datetime import datetime
from time import sleep
from typing import Callable, Optional

from consul import Consul
from timeout_decorator import timeout_decorator

DEFAULT_LOCK_POLL_INTERVAL_GENERATOR = lambda: 5.0

MIN_LOCK_TIMEOUT_IN_SECONDS = 10
MAX_LOCK_TIMEOUT_IN_SECONDS = 86400

logger = logging.getLogger(__name__)


class ConsulLockAcquireTimeout(Exception):
    """
    Raised if the timeout to get a lock expires.
    """


class ConsulLock:
    """
    TODO
    """
    @staticmethod
    def validate_lock_ttl(lock_timeout_in_seconds: float):
        """
        Validates the given lock timeout, raising a `ValueError` if it is invalid.
        :param lock_timeout_in_seconds: the timeout to validate
        :raises ValueError: if the timeout is invalid
        """
        if lock_timeout_in_seconds < MIN_LOCK_TIMEOUT_IN_SECONDS \
                or lock_timeout_in_seconds > MAX_LOCK_TIMEOUT_IN_SECONDS:
            raise ValueError(
                f"Invalid lock timeout: {lock_timeout_in_seconds}. If defined, the timeout must be between "
                f"{MIN_LOCK_TIMEOUT_IN_SECONDS} and {MAX_LOCK_TIMEOUT_IN_SECONDS} (inclusive).")

    def __init__(self, key: str, consul_client: Consul, lock_ttl_in_seconds: float=None,
                 lock_poll_interval_generator: Callable[[], float]=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR):
        """
        TODO
        :param key:
        :param consul_client:
        :param lock_ttl_in_seconds:
        :param lock_poll_period_in_seconds:
        """
        if lock_ttl_in_seconds is not None:
            ConsulLock.validate_lock_ttl(lock_ttl_in_seconds)

        self.key = key
        self.consul_client = consul_client
        self._lock_ttl_in_seconds = lock_ttl_in_seconds
        self.lock_poll_interval_generator = lock_poll_interval_generator

    def acquire(self, blocking: bool=True, timeout: int=None) -> Optional[str]:
        """
        TODO
        :param blocking:
        :param timeout:
        :return:
        """
        session_id = self.consul_client.session.create(
            lock_delay=0, ttl=self._lock_ttl_in_seconds, behavior="delete")

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

    def release(self, session_id: str):
        """
        Release the lock.

        Noop if not locked.
        """
        # Note from: https://github.com/KurToMe/python-consul-lock/blob/0.1.6/consul_lock/lock_impl.py#L144-L149
        # Destroying the session is the safest way to release the lock. We would like to delete the key, but since
        # it is possible that we do not actually have the lock anymore it is best to just destroy the session and
        # let the lock get cleaned up by Consul
        return self.consul_client.session.destroy(session_id=session_id)

    def _acquire_consul_key(self, session_id: str):
        """
        TODO
        :param session_id:
        :return:
        """
        return self.consul_client.kv.put(
            key=self.key, value=str(datetime.utcnow()), acquire=session_id)
