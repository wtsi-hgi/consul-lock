import logging
from logging import Logger, StreamHandler
from consullock.common import PACKAGE_NAME


def create_logger(name: str) -> Logger:
    """
    Creates a logger with the given name.
    :param name: name of the logger (gets prefixed with the package name)
    :return: the created logger
    """
    # TODO: Don't hardcode package name
    logger = logging.getLogger(f"{PACKAGE_NAME}.{name}")
    logger.addHandler(StreamHandler())
    return logger
