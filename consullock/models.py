import datetime
from typing import NamedTuple

from consullock.configuration import DEFAULT_CONSUL_PORT, DEFAULT_CONSUL_TOKEN, DEFAULT_CONSUL_SCHEME, \
    DEFAULT_CONSUL_DATACENTRE, DEFAULT_CONSUL_VERIFY, DEFAULT_CONSUL_CERTIFICATE


class ConsulLockInformation:
    """
    Information about a Consul lock.
    """
    def __init__(self, session_id: str, created: datetime):
        self.session_id = session_id
        self.created = created

