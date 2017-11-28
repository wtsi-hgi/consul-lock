import datetime
from typing import Any


class ConsulLockInformation:
    """
    Information about a Consul lock.
    """
    def __init__(self, key: str, session_id: str, created: datetime):
        self.key = key
        self.session_id = session_id
        self.created = created

    def __eq__(self, other: Any) -> bool:
        return type(other) == type(self) \
               and other.key == self.key \
               and other.session_id == self.session_id \
               and other.created == self.created

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)
