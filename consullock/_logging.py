import logging
from logging import Logger, StreamHandler
from consullock.configuration import PACKAGE_NAME


def create_logger(name: str) -> Logger:
    """
    Creates a logger with the given name.
    :param name: name of the logger (gets prefixed with the package name)
    :return: the created logger
    """
    logger = logging.getLogger(f"{PACKAGE_NAME}.{name}")
    logger.addHandler(StreamHandler())
    return logger
