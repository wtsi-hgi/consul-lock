class BaseException(Exception):
    """
    TODO
    """

class ConsulLockAcquireTimeout(BaseException):
    """
    Raised if the timeout to get a lock expires.
    """
