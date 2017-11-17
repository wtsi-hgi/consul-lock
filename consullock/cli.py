import json
import logging
import os
import sys
from argparse import ArgumentParser, Namespace
from enum import Enum, unique
from typing import NamedTuple, List, Any

from consul import Consul

from consullock._logging import create_logger
from consullock.common import DESCRIPTION, PACKAGE_NAME
from consullock.exceptions import ConsulLockAcquireTimeout
from consullock.json_mappers import ConsulLockInformationJSONEncoder
from consullock.locks import MIN_LOCK_TIMEOUT_IN_SECONDS, MAX_LOCK_TIMEOUT_IN_SECONDS, ConsulLock, PermissionDeniedError

KEY_CLI_PARAMETER = "key"
SESSION_TTL_CLI_LONG_PARAMETER = "session-ttl"
VERBOSE_CLI_SHORT_PARAMETER = "v"
NON_BLOCKING_CLI_LONG_PARAMETER = "non-blocking"
TIMEOUT_CLI_PARAMETER = "timeout"

METHOD_CLI_PARAMETER_ACCESS = "method"

NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE = 0

CONSUL_HOST_ENVIRONMENT_VARIABLE = "CONSUL_HOST"
CONSUL_PORT_ENVIRONMENT_VARIABLE = "CONSUL_PORT"
CONSUL_TOKEN_ENVIRONMENT_VARIABLE = "CONSUL_TOKEN"
CONSUL_SCHEME_ENVIRONMENT_VARIABLE = "CONSUL_SCHEME"
CONSUL_DATACENTRE_ENVIRONMENT_VARIABLE = "CONSUL_DC"
CONSUL_VERIFY_ENVIRONMENT_VARIABLE = "CONSUL_VERIFY"
CONSUL_CERTIFICATE_ENVIRONMENT_VARIABLE = "CONSUL_CERT"

DEFAULT_SESSION_TTL = MAX_LOCK_TIMEOUT_IN_SECONDS
DEFAULT_LOG_VEBOSITY = logging.WARN
DEFAULT_NON_BLOCKING = False
DEFAULT_TIMEOUT = 0.0

DEFAULT_CONSUL_PORT = 8500
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

_NO_DEFAULT_SENTINEL = object()

logger = create_logger(__name__)


class InvalidCliArgumentError(Exception):
    """
    TODO
    """


@unique
class Method(Enum):
    """
    TODO
    """
    LOCK = "lock"
    UNLOCK = "unlock"


# TODO: Just config?
class CliConfiguration(NamedTuple):
    """
    TODO
    """
    method: Method
    key: str
    session_ttl: float = DEFAULT_SESSION_TTL
    log_verbosity: int = DEFAULT_LOG_VEBOSITY
    non_blocking: bool = DEFAULT_NON_BLOCKING
    timeout: float = DEFAULT_TIMEOUT


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


def parse_cli_configration(arguments: List[str]) -> CliConfiguration:
    """
    Parses the configuration passed in via command line arguments.
    :param arguments: CLI arguments
    :return: the configuration
    """
    parser = ArgumentParser(description=DESCRIPTION)

    subparsers = parser.add_subparsers(dest=METHOD_CLI_PARAMETER_ACCESS, help="function")
    subparsers.add_parser(Method.UNLOCK.value, help="release a lock")
    lock_subparser = subparsers.add_parser(Method.LOCK.value, help="acquire a lock")
    lock_subparser.add_argument(
        f"--{SESSION_TTL_CLI_LONG_PARAMETER}", type=float, default=DEFAULT_SESSION_TTL,
        help=f"time to live (ttl) in seconds of the session that will be created to hold the lock. Must be between "
             f"{MIN_LOCK_TIMEOUT_IN_SECONDS}s and {MAX_LOCK_TIMEOUT_IN_SECONDS}s (inclusive). If set to "
             f"{NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE}, the session will not expire")
    lock_subparser.add_argument(f"--{NON_BLOCKING_CLI_LONG_PARAMETER}", action="store_true",
                                default=DEFAULT_NON_BLOCKING, help="do not block if cannot lock straight away")
    lock_subparser.add_argument(f"--{TIMEOUT_CLI_PARAMETER}", default=DEFAULT_TIMEOUT, type=float,
                                help="give up trying to acquire the key after this many seconds (where 0 is never)")


    parser.add_argument(KEY_CLI_PARAMETER, type=str, help="the lock identifier")
    parser.add_argument(f"-{VERBOSE_CLI_SHORT_PARAMETER}", action="count", default=0,
                        help="increase the level of log verbosity (add multiple increase further)")

    parsed_arguments = parser.parse_args(arguments)
    session_ttl = _get_parameter_argument(SESSION_TTL_CLI_LONG_PARAMETER, parsed_arguments, default=None)
    if session_ttl == NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE:
        session_ttl = None
    return CliConfiguration(
        method=Method(_get_parameter_argument(METHOD_CLI_PARAMETER_ACCESS, parsed_arguments)),
        key=_get_parameter_argument(KEY_CLI_PARAMETER, parsed_arguments),
        session_ttl=session_ttl,
        log_verbosity=_get_verbosity(parsed_arguments),
        # TODO: If config for release, these values are meaningless! Should be differnent subclass and not need "default"
        non_blocking=_get_parameter_argument(
            NON_BLOCKING_CLI_LONG_PARAMETER, parsed_arguments, default=DEFAULT_NON_BLOCKING),
        timeout=_get_parameter_argument(TIMEOUT_CLI_PARAMETER, parsed_arguments or None, default=DEFAULT_TIMEOUT))


def _get_verbosity(parsed_arguments: Namespace) -> int:
    """
    Gets the verbosity level from the parsed arguments.
    :param parsed_arguments: the parsed arguments
    :return: the verbosity level implied
    """
    verbosity = DEFAULT_LOG_VEBOSITY - \
                (int(_get_parameter_argument(VERBOSE_CLI_SHORT_PARAMETER, parsed_arguments)) * 10)
    if verbosity < 10:
        raise InvalidCliArgumentError("Cannot provide any further logging - reduce log verbosity")
    assert verbosity <= logging.CRITICAL
    return verbosity


def _get_parameter_argument(parameter: str, parsed_arguments: Namespace, default: Any=_NO_DEFAULT_SENTINEL) -> Any:
    """
    Gets the argument associated to the given parameter in the given parsed arguments.
    :param parameter: the parameter of interest
    :param parsed_arguments: the namespace resulting in the parsing of the argumentst
    :param default: default to return if no argument for the given parameter
    :return: the associated argument
    :raises KeyError: if the parameter does not exist
    """
    value = vars(parsed_arguments).get(parameter.replace("-", "_"), default)
    if value == _NO_DEFAULT_SENTINEL:
        raise KeyError(parameter)
    return value


def get_consul_configuration_from_environment() -> ConsulConfiguration:
    """
    Gets credentials to use Consul from the environment.
    :return: configuration
    :raises KeyError: if a required environment variable has not been set
    """
    host = os.environ[CONSUL_HOST_ENVIRONMENT_VARIABLE]
    if "://" in host:
        raise EnvironmentError(
            f"Invalid host: {host}. Do not specify scheme in host - set that in {CONSUL_SCHEME_ENVIRONMENT_VARIABLE}")

    return ConsulConfiguration(
        host = host,
        port=os.environ.get(CONSUL_PORT_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_PORT),
        token=os.environ.get(CONSUL_TOKEN_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_TOKEN),
        scheme=os.environ.get(CONSUL_SCHEME_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_SCHEME),
        datacentre=os.environ.get(CONSUL_DATACENTRE_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_DATACENTRE),
        verify=os.environ.get(CONSUL_VERIFY_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_VERIFY),
        certificate=os.environ.get(CONSUL_CERTIFICATE_ENVIRONMENT_VARIABLE, DEFAULT_CONSUL_CERTIFICATE))


def main(cli_arguments: List[str]):
    """
    Entrypoint.
    """
    try:
        cli_configuration = parse_cli_configration(cli_arguments)
    except InvalidCliArgumentError as e:
        logger.error(e)
        exit(INVALID_CLI_ARGUMENT_EXIT_CODE)

    if cli_configuration.log_verbosity:
        logging.getLogger(PACKAGE_NAME).setLevel(cli_configuration.log_verbosity)

    try:
        consul_configuration = get_consul_configuration_from_environment()
    except KeyError as e:
        logger.error(f"Cannot connect to Consul - the environment variable {e.args[0]} must be set")
        exit(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE)
    except EnvironmentError as e:
        logger.error(e)
        exit(INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE)

    # TODO: Removed coupling to Consul library
    consul_client = Consul(
        host=consul_configuration.host,
        port=consul_configuration.port,
        token=consul_configuration.token,
        scheme=consul_configuration.scheme,
        dc=consul_configuration.datacentre,
        verify=consul_configuration.verify,
        cert=consul_configuration.certificate)
    # Work around for https://github.com/cablehead/python-consul/issues/170
    consul_client.http.session.headers.update({"X-Consul-Token": consul_configuration.token})

    consul_lock = ConsulLock(
        key=cli_configuration.key,
        consul_client=consul_client,
        session_ttl_in_seconds=cli_configuration.session_ttl)

    try:
        if cli_configuration.method == Method.LOCK:
            lock_information = consul_lock.acquire(
                blocking=not cli_configuration.non_blocking, timeout=cli_configuration.timeout)
            print(json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, sort_keys=True))
        elif cli_configuration.method == Method.UNLOCK:
            consul_lock.release()
    except PermissionDeniedError as e:
        error_message = f"Invalid credentials - are you sure you have set {CONSUL_TOKEN_ENVIRONMENT_VARIABLE} " \
                        f"correctly (currently set to \"{consul_configuration.token}\")?"
        logger.error(error_message)
        logger.debug(e)
        exit(PERMISSION_DENIED_EXIT_CODE)
    # TODO: This exception only relates to acquire method
    except ConsulLockAcquireTimeout as e:
        logger.debug(e)
        exit(LOCK_ACQUIRE_TIMEOUT_EXIT_CODE)

    exit(SUCCESS_EXIT_CODE)


if __name__ == "__main__":
    main(sys.argv[1:])