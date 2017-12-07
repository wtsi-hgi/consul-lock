import argparse
import errno
import json
import logging
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from enum import Enum, unique
from os.path import normpath
from typing import List, Any

import demjson as demjson
import itertools

from consullock._logging import create_logger
from consullock.configuration import DEFAULT_SESSION_TTL, DEFAULT_LOG_VERBOSITY, DEFAULT_NON_BLOCKING, \
    DEFAULT_TIMEOUT, SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    INVALID_CLI_ARGUMENT_EXIT_CODE, PERMISSION_DENIED_EXIT_CODE, LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, \
    MIN_LOCK_TIMEOUT_IN_SECONDS, MAX_LOCK_TIMEOUT_IN_SECONDS, CONSUL_TOKEN_ENVIRONMENT_VARIABLE, \
    get_consul_configuration_from_environment, INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    PACKAGE_NAME, DESCRIPTION, INVALID_KEY_EXIT_CODE, INVALID_SESSION_TTL_EXIT_CODE, DEFAULT_REGEX_KEY_ENABLED, \
    UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, VERSION, DEFAULT_LOCK_POLL_INTERVAL_GENERATOR, DEFAULT_METADATA
from consullock.exceptions import LockAcquireTimeoutError, PermissionDeniedConsulError, \
    InvalidEnvironmentVariableError, InvalidSessionTtlValueError, DoubleSlashKeyError, NonNormalisedKeyError
from consullock.json_mappers import ConsulLockInformationJSONEncoder
from consullock.managers import ConsulLockManager, LOCK_EVENT_LISTENER

KEY_CLI_PARAMETER = "key"
SESSION_TTL_CLI_LONG_PARAMETER = "session-ttl"
VERBOSE_CLI_SHORT_PARAMETER = "v"
REGEX_KEY_ENABLED_SHORT_PARAMETER = "r"
NON_BLOCKING_CLI_LONG_PARAMETER = "non-blocking"
TIMEOUT_CLI_lONG_PARAMETER = "timeout"
METADATA_CLI_lONG_PARAMETER = "metadata"
ON_BEFORE_LOCK_LONG_PARAMETER = "on-before-lock"
ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER = "on-already-locked"
LOCK_POLL_INTERVAL_SHORT_PARAMETER = "i"

ACTION_CLI_PARAMETER_ACCESS = "action"

NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE = 0

_NO_DEFAULT_SENTINEL = object()

logger = create_logger(__name__)


class InvalidCliArgumentError(Exception):
    """
    Raised when an invalid CLI argument has been given.
    """


@unique
class Action(Enum):
    """
    Actions available on the CLI.
    """
    LOCK = "lock"
    UNLOCK = "unlock"


class CliConfiguration:
    """
    Configuration, set via the CLI.
    """
    def __init__(self, key: str, log_verbosity: int=DEFAULT_LOG_VERBOSITY, session_ttl: float=DEFAULT_SESSION_TTL):
        self.key = key
        self.log_verbosity = log_verbosity
        self.session_ttl = session_ttl


class CliUnlockConfiguration(CliConfiguration):
    """
    Configuration for unlocking a lock, set via the CLI.
    """
    def __init__(self, *args, regex_key_enabled: bool=DEFAULT_REGEX_KEY_ENABLED, **kwargs):
        super().__init__(*args, **kwargs)
        self.regex_key_enabled = regex_key_enabled


class CliLockConfiguration(CliConfiguration):
    """
    Configuration for locking a lock, set via the CLI.
    """
    def __init__(self, *args, non_blocking: bool=DEFAULT_NON_BLOCKING, timeout: float=DEFAULT_TIMEOUT,
                 metadata: Any=DEFAULT_METADATA, on_before_locked_executables: List[str]=None,
                 on_lock_already_locked_executables: List[str]=None,
                 lock_poll_interval: float=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1), **kwargs):
        super().__init__(*args, **kwargs)
        self.non_blocking = non_blocking
        self.timeout = timeout
        self.metadata = metadata
        self.on_before_locked_executables = on_before_locked_executables \
            if on_before_locked_executables is not None else []
        self.on_lock_already_locked_executables = on_lock_already_locked_executables \
            if on_lock_already_locked_executables is not None else []
        self.lock_poll_interval = lock_poll_interval


class _ParseJsonAction(argparse.Action):
    """
    Action that parses JSON (in a non-strict way).
    """
    def __call__(self, parser, args, values, option_string=None):
        try:
            value = demjson.decode(values, strict=False)
        except demjson.JSONDecodeError as e:
            raise InvalidCliArgumentError(f"Unable to parse value for \"{self.dest}\" as JSON: {values}") from e
        setattr(args, self.dest, value)


def _create_parser() -> ArgumentParser:
    """
    Creates argument parser for the CLI.
    :return: the argument parser
    """
    parser = ArgumentParser(description=f"{DESCRIPTION} (v{VERSION})")
    parser.add_argument(
        f"-{VERBOSE_CLI_SHORT_PARAMETER}", action="count", default=0,
        help="increase the level of log verbosity (add multiple increase further)")
    subparsers = parser.add_subparsers(dest=ACTION_CLI_PARAMETER_ACCESS, help="action")

    unlock_subparser = subparsers.add_parser(Action.UNLOCK.value, help="release a lock")
    unlock_subparser.add_argument(
        f"-{REGEX_KEY_ENABLED_SHORT_PARAMETER}", action="store_true", default=DEFAULT_REGEX_KEY_ENABLED,
        help="whether the key should be treated as a regular expression and to release all matching locks")

    lock_subparser = subparsers.add_parser(Action.LOCK.value, help="acquire a lock")
    lock_subparser.add_argument(
        f"--{SESSION_TTL_CLI_LONG_PARAMETER}", type=float, default=DEFAULT_SESSION_TTL,
        help=f"time to live (ttl) in seconds of the session that will be created to hold the lock. Must be between "
             f"{MIN_LOCK_TIMEOUT_IN_SECONDS}s and {MAX_LOCK_TIMEOUT_IN_SECONDS}s (inclusive). If set to "
             f"{NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE}, the session will not expire")
    lock_subparser.add_argument(
        f"--{NON_BLOCKING_CLI_LONG_PARAMETER}", action="store_true",
        default=DEFAULT_NON_BLOCKING, help="do not block if cannot lock straight away")
    lock_subparser.add_argument(
        f"--{TIMEOUT_CLI_lONG_PARAMETER}", default=DEFAULT_TIMEOUT, type=float,
        help="give up trying to acquire the key after this many seconds (where 0 is never)")
    lock_subparser.add_argument(
        f"--{METADATA_CLI_lONG_PARAMETER}", default=DEFAULT_METADATA, type=str, action=_ParseJsonAction,
        help="additional metadata to add to the lock information (will be converted to JSON)")
    lock_subparser.add_argument(
        f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", default=None, type=str, nargs="+", action="append",
        help="path to executable that is to be called before an attempt is made to acquire a lock, where the lock key "
             "is passed as the first argument. Any failures of this executable are ignored")
    lock_subparser.add_argument(
        f"--{ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER}", default=None, type=str, nargs="+", action="append",
        help="path to executable that is to be called after an attempt has been made to acquire a lock but failed due "
             "to the lock already been taken, where the lock key is passed as the first argument. Any failures of this "
             "executable are ignored")
    lock_subparser.add_argument(
        f"-{LOCK_POLL_INTERVAL_SHORT_PARAMETER}", default=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1), type=float,
        help="number of seconds between polls to acquire a locked lock")

    for subparser in [unlock_subparser, lock_subparser]:
        subparser.add_argument(
            KEY_CLI_PARAMETER, type=str, help="the lock identifier")

    return parser


_argument_parser = _create_parser()


def parse_cli_configration(arguments: List[str]) -> CliConfiguration:
    """
    Parses the configuration passed in via command line arguments.
    :param arguments: CLI arguments
    :return: the configuration
    """
    try:
        parsed_arguments = _argument_parser.parse_args(arguments)
    except SystemExit as e:
        if e.code == SUCCESS_EXIT_CODE:
            raise e
        raise InvalidCliArgumentError() from e

    action = parsed_arguments.action
    if action is None:
        _argument_parser.print_help()
        exit(INVALID_CLI_ARGUMENT_EXIT_CODE)
    parsed_action = Action(_get_parameter_argument(ACTION_CLI_PARAMETER_ACCESS, parsed_arguments))

    session_ttl = _get_parameter_argument(SESSION_TTL_CLI_LONG_PARAMETER, parsed_arguments, default=None)
    if session_ttl == NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE:
        session_ttl = None

    shared_parameters = dict(
        key=_get_parameter_argument(KEY_CLI_PARAMETER, parsed_arguments),
        log_verbosity=_get_verbosity(parsed_arguments), session_ttl=session_ttl)

    if parsed_action == Action.LOCK:
        return CliLockConfiguration(
            **shared_parameters,
            non_blocking=_get_parameter_argument(
                NON_BLOCKING_CLI_LONG_PARAMETER, parsed_arguments, default=DEFAULT_NON_BLOCKING),
            timeout=_get_parameter_argument(
                TIMEOUT_CLI_lONG_PARAMETER, parsed_arguments, default=DEFAULT_TIMEOUT),
            metadata=_get_parameter_argument(
                METADATA_CLI_lONG_PARAMETER, parsed_arguments, default=DEFAULT_METADATA),
            on_before_locked_executables=list(itertools.chain(*_get_parameter_argument(
                ON_BEFORE_LOCK_LONG_PARAMETER, parsed_arguments) or [])),
            on_lock_already_locked_executables=list(itertools.chain(*_get_parameter_argument(
                ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER, parsed_arguments) or [])),
            lock_poll_interval=_get_parameter_argument(
                LOCK_POLL_INTERVAL_SHORT_PARAMETER, parsed_arguments, default=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1)))
    else:
        return CliUnlockConfiguration(
            **shared_parameters,
            regex_key_enabled=_get_parameter_argument(
                REGEX_KEY_ENABLED_SHORT_PARAMETER, parsed_arguments, default=DEFAULT_REGEX_KEY_ENABLED))


def _get_verbosity(parsed_arguments: Namespace) -> int:
    """
    Gets the verbosity level from the parsed arguments.
    :param parsed_arguments: the parsed arguments
    :return: the verbosity level implied
    """
    verbosity = DEFAULT_LOG_VERBOSITY - \
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


def _lock(lock_manager: ConsulLockManager, configuration: CliLockConfiguration):
    """
    Locks a lock.
    :param lock_manager: the lock manager
    :param configuration: the configuration required to lock the lock
    """
    def generate_event_listener_caller(executables: List[str]) -> LOCK_EVENT_LISTENER:
        def event_listener_caller(key: str):
            for executable in executables:
                try:
                    process = subprocess.Popen([executable, key], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                    output, stderr = process.communicate()
                    if len(stderr) > 0:
                        logger.info(f"stderr from executing \"{executable}\": {stderr.decode('utf-8').strip()}")
                    if process.returncode != 0:
                        logger.error(f"Error when executing \"{executable}\": return code was {process.returncode}")
                    # Not falling over if event listener does!
                except OSError as e:
                    common_error_string = f"Could not execute \"{executable}\":"
                    if e.errno == errno.ENOEXEC:
                        logger.warning(f"{common_error_string} {e} (perhaps the executable needs a shebang?)")
                    else:
                        logger.warning(f"{common_error_string} {e}")

        return event_listener_caller

    event_listeners: LOCK_EVENT_LISTENER = {}
    if configuration.on_before_locked_executables is not None:
        event_listeners["on_before_lock"] = generate_event_listener_caller(
            configuration.on_before_locked_executables)
    if configuration.on_lock_already_locked_executables is not None:
        event_listeners["on_lock_already_locked"] = generate_event_listener_caller(
            configuration.on_lock_already_locked_executables)

    try:
        lock_information = lock_manager.acquire(
            key=configuration.key, blocking=not configuration.non_blocking,
            timeout=configuration.timeout, metadata=configuration.metadata, **event_listeners,
            lock_poll_interval_generator=lambda i: configuration.lock_poll_interval)
    except LockAcquireTimeoutError as e:
        logger.debug(e)
        logger.error(f"Timed out whilst waiting to acquire lock: {configuration.key}")
        print(json.dumps(None))
        exit(LOCK_ACQUIRE_TIMEOUT_EXIT_CODE)

    print(json.dumps(lock_information, cls=ConsulLockInformationJSONEncoder, sort_keys=True))

    if lock_information is None:
        logger.error(f"Unable to acquire lock: {configuration.key}")
        exit(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE)

    exit(SUCCESS_EXIT_CODE)


def _unlock(lock_manager: ConsulLockManager, configuration: CliUnlockConfiguration):
    """
    Unlocks a lock.
    :param lock_manager: the lock manager
    :param configuration: the configuration required to unlock the lock
    """
    if configuration.regex_key_enabled:
        release_information = sorted(list(lock_manager.release_regex(key_regex=configuration.key)))
    else:
        release_information = lock_manager.release(key=configuration.key)
    print(json.dumps(release_information))

    exit(SUCCESS_EXIT_CODE)


def main(cli_arguments: List[str]):
    """
    Entrypoint.
    :param cli_arguments: arguments passed in via the CLI
    :raises SystemExit: always raised
    """
    try:
        cli_configuration = parse_cli_configration(cli_arguments)
    except InvalidCliArgumentError as e:
        logger.error(e)
        exit(INVALID_CLI_ARGUMENT_EXIT_CODE)
    except SystemExit as e:
        exit(e.code)

    if cli_configuration.log_verbosity:
        logging.getLogger(PACKAGE_NAME).setLevel(cli_configuration.log_verbosity)

    try:
        consul_configuration = get_consul_configuration_from_environment()
    except KeyError as e:
        logger.error(f"Cannot connect to Consul - the environment variable {e.args[0]} must be set")
        exit(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE)
    except InvalidEnvironmentVariableError as e:
        logger.error(e)
        exit(INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE)

    try:
        lock_manager = ConsulLockManager(
            consul_configuration=consul_configuration, session_ttl_in_seconds=cli_configuration.session_ttl)
    except InvalidSessionTtlValueError as e:
        logger.error(e)
        exit(INVALID_SESSION_TTL_EXIT_CODE)

    try:
        if isinstance(cli_configuration, CliLockConfiguration):
            _lock(lock_manager, cli_configuration)
        else:
            _unlock(lock_manager, cli_configuration)
    except PermissionDeniedConsulError as e:
        error_message = f"Invalid credentials - are you sure you have set {CONSUL_TOKEN_ENVIRONMENT_VARIABLE} " \
                        f"correctly?"
        logger.debug(e)
        logger.error(error_message)
        exit(PERMISSION_DENIED_EXIT_CODE)
    except DoubleSlashKeyError as e:
        logger.debug(e)
        logger.error(f"Double slashes \"//\" in keys get converted into single slashes \"/\" - please use a "
                     f"single slash if this is intended: {cli_configuration.key}")
        exit(INVALID_KEY_EXIT_CODE)
    except NonNormalisedKeyError as e:
        logger.debug(e)
        logger.error(f"Key paths must be normalised - use \"{normpath(e.key)}\" if this key was intended: "
                     f"{cli_configuration.key}")
        exit(INVALID_KEY_EXIT_CODE)


def entrypoint():
    """
    Entrypoint to be used by CLI.
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    entrypoint()
