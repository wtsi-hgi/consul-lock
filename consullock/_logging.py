import logging
from logging import Logger, StreamHandler

LOGGING_NAMESPACE = "consullock"


def create_logger(name: str) -> Logger:
    """
    Creates a logger with the given name.
    :param name: name of the logger (gets prefixed with the package name)
    :return: the created logger
    """
    # TODO: Don't hardcode package name
    logger = logging.getLogger(f"{LOGGING_NAMESPACE}.{name}")
    logger.addHandler(StreamHandler())
    return logger
