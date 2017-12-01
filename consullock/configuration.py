import logging
import os
from typing import NamedTuple


PACKAGE_NAME = "consullock"
DESCRIPTION = "Tool to use locks in Consul"
EXECUTABLE_NAME = "consul-lock"

DEFAULT_LOCK_POLL_INTERVAL_GENERATOR = lambda: 1.0
MIN_LOCK_TIMEOUT_IN_SECONDS = 10
MAX_LOCK_TIMEOUT_IN_SECONDS = 86400

DEFAULT_SESSION_TTL = MAX_LOCK_TIMEOUT_IN_SECONDS
DEFAULT_CONSUL_PORT = 8500
DEFAULT_LOG_VERBOSITY = logging.WARN
DEFAULT_NON_BLOCKING = False
DEFAULT_TIMEOUT = 0.0
DEFAULT_REGEX_KEY_ENABLED = False
DEFAULT_CONSUL_TOKEN = None
DEFAULT_CONSUL_SCHEME = "http"
DEFAULT_CONSUL_DATACENTRE = None
DEFAULT_CONSUL_VERIFY = True
DEFAULT_CONSUL_CERTIFICATE = None

SUCCESS_EXIT_CODE = 0
MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE = 1
INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE = 2
INVALID_CLI_ARGUMENT_EXIT_CODE = 3
PERMISSION_DENIED_EXIT_CODE = 4
LOCK_ACQUIRE_TIMEOUT_EXIT_CODE = 5
INVALID_KEY_EXIT_CODE = 6
INVALID_SESSION_TTL_EXIT_CODE = 7
UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE = 100

CONSUL_ADDRESS_ENVIRONMENT_VARIABLE = "CONSUL_HTTP_ADDR"
CONSUL_TOKEN_ENVIRONMENT_VARIABLE = "CONSUL_HTTP_TOKEN"
CONSUL_SCHEME_ENVIRONMENT_VARIABLE = "CONSUL_SCHEME"
CONSUL_DATACENTRE_ENVIRONMENT_VARIABLE = "CONSUL_DC"
CONSUL_VERIFY_ENVIRONMENT_VARIABLE = "CONSUL_HTTP_SSL_VERIFY"
CONSUL_CERTIFICATE_ENVIRONMENT_VARIABLE = "CONSUL_CLIENT_CERT"


# Workaround for cyclic dependency when using logger in this module
def _get_logger():
    global _logger
    if _logger is None:
        from consullock._logging import create_logger
        _logger = create_logger(__name__)
    return _logger


_logger = None


class ConsulConfiguration(NamedTuple):
    """
    Configuration for Consul server.
    """
    host: str
    port: int = DEFAULT_CONSUL_PORT
    token: str = DEFAULT_CONSUL_TOKEN
    scheme: str = DEFAULT_CONSUL_SCHEME
    datacentre: str = DEFAULT_CONSUL_DATACENTRE
    verify: bool = DEFAULT_CONSUL_VERIFY
    certificate: str = DEFAULT_CONSUL_CERTIFICATE


def get_consul_configuration_from_environment() -> ConsulConfiguration:
    """
    Gets configuration on how to connect to Consul from the environment.
    :return: the configuration derived from the environment
    :raises KeyError: if a required environment variable has not been set
    """
    address = os.environ[CONSUL_ADDRESS_ENVIRONMENT_VARIABLE]
    if "://" in address:
        raise EnvironmentError(f"Invalid host: {address}. Do not specify scheme in host - set that in "
                               f"{CONSUL_SCHEME_ENVIRONMENT_VARIABLE}")

    host_port_split = address.split(":")
    host = host_port_split[0]
    if len(host_port_split) == 1:
        _get_logger().info(
            f"No port specified in address read from the environment - using default port: {DEFAULT_CONSUL_PORT}")
        port = DEFAULT_CONSUL_PORT
    else:
        port = host_port_split[1]

    return ConsulConfiguration(
        host=host,
        port=port,
        token=os.environ.get(CONSUL_TOKEN_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_TOKEN),
        scheme=os.environ.get(CONSUL_SCHEME_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_SCHEME),
        datacentre=os.environ.get(CONSUL_DATACENTRE_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_DATACENTRE),
        verify=os.environ.get(CONSUL_VERIFY_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_VERIFY),
        certificate=os.environ.get(CONSUL_CERTIFICATE_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_CERTIFICATE))
