class ConsulLockBaseError(Exception):
    """
    TODO
    """


class LockAcquireTimeoutError(ConsulLockBaseError):
    """
    Raised if the timeout to get a lock expires.
    """


class UnusableStateException(ConsulLockBaseError):
    """
    Raised upon attempt to use instance that is in an unusable state.
    """


class ConsulConnectionError(ConsulLockBaseError):
    """
    Wrapped exception from the underlying library dealing with Consul.
    """


class PermissionDeniedConsulError(ConsulConnectionError):
    """
    Raised when Consul has refused to act due to a permission error.
    """


class SessionLostConsulError(ConsulConnectionError):
    """
    Raised if a Consul session is lost in the middle of an operation.
    """


class InvalidKeyError(ConsulLockBaseError):
    """
    Raised if a key name is invalid.
    """
    def __init__(self, key: str):
        super().__init__(f"Invalid key name: {key}")
        self.key = key


class DoubleSlashKeyError(InvalidKeyError):
    """
    Raised if a key uses double slash.
    """


class InvalidEnvironmentVariableError(ConsulLockBaseError):
    """
    TODO
    """
    def __init__(self, message: str, variable: str):
        super().__init__(message)
        self.variable = variable


class InvalidSessionTtlValueError(ConsulLockBaseError):
    """
    TODO
    """