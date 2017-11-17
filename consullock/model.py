import datetime


class ConsulLockInformation:
    """
    Information about a Consul lock.
    """
    def __init__(self, session_id: str, created: datetime):
        self.session_id = session_id
        self.created = created
