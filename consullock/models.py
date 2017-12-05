import datetime
from typing import Any


class ConsulLockInformation:
    """
    Information about a Consul lock.
    """
    def __init__(self, key: str, session_id: str, created: datetime, seconds_to_lock: float, metadata: Any=None):
        self.key = key
        self.session_id = session_id
        self.created = created
        self.seconds_to_lock = seconds_to_lock
        self.metadata = metadata

    def __eq__(self, other: Any) -> bool:
        return type(other) == type(self) \
               and other.key == self.key \
               and other.session_id == self.session_id \
               and other.created == self.created \
               and other.seconds_to_lock == self.seconds_to_lock \
               and other.metadata == self.metadata

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)
