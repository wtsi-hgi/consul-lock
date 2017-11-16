from typing import Collection


class Session:
    """
    Consul session.
    """
    def __init__(self, id: str, lock_ids: Collection[str]=None):
        self.id = id
        self.lock_ids = set(lock_ids) if lock_ids is not None else set()