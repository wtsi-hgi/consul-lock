import logging
import os
import sys
from argparse import ArgumentParser, Namespace, ArgumentDefaultsHelpFormatter
from enum import Enum, unique
from typing import NamedTuple, List, Any

from consul import Consul
from cli import MIN_LOCK_TIMEOUT_IN_SECONDS, MAX_LOCK_TIMEOUT_IN_SECONDS

from locks import ConsulLock

KEY_CLI_PARAMETER = "key"
SESSION_TTL_CLI_PARAMETER = "session-ttl"
_METHOD_CLI_IMPLICIT_PARAMETER = "method"

CONSUL_HOST_ENVIRONMENT_VARIABLE = "CONSUL_HOST"
CONSUL_PORT_ENVIRONMENT_VARIABLE = "CONSUL_PORT"
CONSUL_TOKEN_ENVIRONMENT_VARIABLE = "CONSUL_TOKEN"
CONSUL_SCHEME_ENVIRONMENT_VARIABLE = "CONSUL_SCHEME"
CONSUL_DATACENTRE_ENVIRONMENT_VARIABLE = "CONSUL_DC"
CONSUL_VERIFY_ENVIRONMENT_VARIABLE = "CONSUL_VERIFY"
CONSUL_CERTIFICATE_ENVIRONMENT_VARIABLE = "CONSUL_CERT"

DEFAULT_SESSION_TTL = None

DEFAULT_CONSUL_PORT = 8500
DEFAULT_CONSUL_TOKEN = None
DEFAULT_CONSUL_SCHEME = "http"
DEFAULT_CONSUL_DATACENTRE = None
DEFAULT_CONSUL_VERIFY = True
DEFAULT_CONSUL_CERTIFICATE = None

MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE = 1
INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE = 2

logger = logging.getLogger(__name__)


@unique
class Method(Enum):
    """
    TODO
    """
    # TODO: Aliases (aquire)
    LOCK = "lock"
    UNLOCK = "unlock"


class CliConfiguration(NamedTuple):
    """
    TODO
    """
    method: Method
    key: str
    session_ttl: float = DEFAULT_SESSION_TTL


class ConsulConfiguration(NamedTuple):
    """
    TODO
    """
    host: str
    port: int = DEFAULT_CONSUL_PORT
    token: str = DEFAULT_CONSUL_TOKEN
    scheme: str = DEFAULT_CONSUL_SCHEME
    datacentre: str = DEFAULT_CONSUL_DATACENTRE
    verify: bool = DEFAULT_CONSUL_VERIFY
    certificate: str = DEFAULT_CONSUL_CERTIFICATE


def parse_cli_configration(arguments: List[str]):
    """
    TODO
    :param arguments:
    :return:
    """
    parser = ArgumentParser(description="TODO", formatter_class=ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(help="TODO", dest=_METHOD_CLI_IMPLICIT_PARAMETER)

    lock_subparser = subparsers.add_parser(Method.LOCK.value, help="TODO")
    lock_subparser.add_argument(
        f"--{SESSION_TTL_CLI_PARAMETER}", type=float, default=DEFAULT_SESSION_TTL,
        help=f"Time to live (ttl) of the session that will be created to hold the lock. Must be between {MIN_LOCK_TIMEOUT_IN_SECONDS} and {MAX_LOCK_TIMEOUT_IN_SECONDS} (inclusive). If not defined, the session "
             "will not expire.")

    unlock_subparser = subparsers.add_parser(Method.UNLOCK.value, help="TODO")

    parser.add_argument(KEY_CLI_PARAMETER, type=str, help="TODO")

    parsed_arguments = parser.parse_args(arguments)
    return CliConfiguration(
        method=Method(_get_parameter_argument(_METHOD_CLI_IMPLICIT_PARAMETER, parsed_arguments)),
        key=_get_parameter_argument(KEY_CLI_PARAMETER, parsed_arguments),
        lock_ttl=_get_parameter_argument(SESSION_TTL_CLI_PARAMETER, parsed_arguments))


def _get_parameter_argument(parameter: str, parsed_arguments: Namespace) -> Any:
    """
    Gets the argument associated to the given parameter in the given parsed arguments.
    :param parameter: the parameter of interest
    :param parsed_arguments: the namespace resulting in the parsing of the argumentst
    :return: the associated argument
    :raises KeyError: if the parameter does not exist
    """
    return vars(parsed_arguments)[parameter.replace("-", "_")]


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


def main():
    """
    TODO
    :return:
    """
    cli_configuration = parse_cli_configration(sys.argv[1:])
    try:
        consul_configuration = get_consul_configuration_from_environment()
    except KeyError as e:
        logger.error(f"Cannot connect to Consul - the environment variable {e.args[0]} must be set")
        exit(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE)
    except EnvironmentError as e:
        logger.error(e)
        exit(INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE)

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

    if cli_configuration.method == Method.LOCK:
        # TODO: Timeout
        consul_lock.acquire()
    else:
        # TODO: session_id...
        consul_lock.release()


if __name__ == "__main__":
    main()