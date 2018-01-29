import argparse
import errno
import itertools
import json
import logging
import subprocess
import sys
from argparse import ArgumentParser
from enum import Enum, unique
from os.path import normpath
from typing import List, Any, Optional, Dict

import demjson as demjson

from consullock._logging import create_logger
from consullock.configuration import DEFAULT_SESSION_TTL, DEFAULT_LOG_VERBOSITY, DEFAULT_NON_BLOCKING, \
    DEFAULT_TIMEOUT, SUCCESS_EXIT_CODE, MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    INVALID_CLI_ARGUMENT_EXIT_CODE, PERMISSION_DENIED_EXIT_CODE, LOCK_ACQUIRE_TIMEOUT_EXIT_CODE, \
    MIN_LOCK_TIMEOUT_IN_SECONDS, MAX_LOCK_TIMEOUT_IN_SECONDS, CONSUL_TOKEN_ENVIRONMENT_VARIABLE, \
    get_consul_configuration_from_environment, INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE, \
    PACKAGE_NAME, DESCRIPTION, INVALID_KEY_EXIT_CODE, INVALID_SESSION_TTL_EXIT_CODE, DEFAULT_REGEX_KEY_ENABLED, \
    UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE, VERSION, DEFAULT_LOCK_POLL_INTERVAL_GENERATOR, DEFAULT_METADATA, \
    ConsulConfiguration
from consullock.exceptions import LockAcquireTimeoutError, PermissionDeniedConsulError, \
    InvalidEnvironmentVariableError, InvalidSessionTtlValueError, DoubleSlashKeyError, NonNormalisedKeyError
from consullock.json_mappers import ConsulLockInformationJSONEncoder
from consullock.managers import ConsulLockManager, LockEventListener
from consullock.models import ConnectedConsulLockInformation

KEY_PARAMETER = "key"
EXECUTABLE_PARAMETER = "executable"
SESSION_TTL_LONG_PARAMETER = "session-ttl"
VERBOSE_SHORT_PARAMETER = "v"
REGEX_KEY_ENABLED_SHORT_PARAMETER = "r"
NON_BLOCKING_LONG_PARAMETER = "non-blocking"
TIMEOUT_LONG_PARAMETER = "timeout"
METADATA_LONG_PARAMETER = "metadata"
ON_BEFORE_LOCK_LONG_PARAMETER = "on-before-lock"
ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER = "on-already-locked"
LOCK_POLL_INTERVAL_SHORT_PARAMETER = "i"

ACTION_CLI_PARAMETER_ACCESS = "action"

NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE = 0

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
    EXECUTE = "execute"


class CliConfiguration:
    """
    Configuration, set via the CLI.
    """
    def __init__(self, key: str, *, log_verbosity: int=DEFAULT_LOG_VERBOSITY, session_ttl: float=DEFAULT_SESSION_TTL):
        self.key = key
        self.log_verbosity = log_verbosity
        self.session_ttl = session_ttl


class CliUnlockConfiguration(CliConfiguration):
    """
    Configuration for unlocking a lock, set via the CLI.
    """
    def __init__(self, key: str, *, regex_key_enabled: bool=DEFAULT_REGEX_KEY_ENABLED, **kwargs):
        super().__init__(key, **kwargs)
        self.regex_key_enabled = regex_key_enabled


class CliLockConfiguration(CliConfiguration):
    """
    Configuration for locking a lock, set via the CLI.
    """
    def __init__(self, key: str, *, non_blocking: bool=DEFAULT_NON_BLOCKING, timeout: float=DEFAULT_TIMEOUT,
                 metadata: Any=DEFAULT_METADATA, on_before_locked_executables: List[str]=None,
                 on_lock_already_locked_executables: List[str]=None,
                 lock_poll_interval: float=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1), **kwargs):
        super().__init__(key, **kwargs)
        self.non_blocking = non_blocking
        self.timeout = timeout
        self.metadata = metadata
        self.on_before_locked_executables = on_before_locked_executables \
            if on_before_locked_executables is not None else []
        self.on_lock_already_locked_executables = on_lock_already_locked_executables \
            if on_lock_already_locked_executables is not None else []
        self.lock_poll_interval = lock_poll_interval


class CliLockAndExecuteConfiguration(CliLockConfiguration):
    """
    TODO
    """
    def __init__(self, key: str, executable: str, **kwargs):
        super().__init__(key, **kwargs)
        self.executable = executable


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
    parser = ArgumentParser(prog=PACKAGE_NAME, description=f"{DESCRIPTION} (v{VERSION})")
    parser.add_argument(
        f"-{VERBOSE_SHORT_PARAMETER}", action="count", default=0,
        help="increase the level of log verbosity (add multiple increase further)")
    subparsers = parser.add_subparsers(dest=ACTION_CLI_PARAMETER_ACCESS, help="action")

    unlock_subparser = subparsers.add_parser(Action.UNLOCK.value, help="release a lock")
    unlock_subparser.add_argument(
        f"-{REGEX_KEY_ENABLED_SHORT_PARAMETER}", action="store_true", default=DEFAULT_REGEX_KEY_ENABLED,
        help="whether the key should be treated as a regular expression and to release all matching locks")

    lock_subparser = subparsers.add_parser(Action.LOCK.value, help="acquire a lock")
    lock_and_execute_subparser = subparsers.add_parser(Action.EXECUTE.value, help="call executable whilst holding lock")

    for subparser in (lock_subparser, lock_and_execute_subparser):
        subparser.add_argument(
            f"--{SESSION_TTL_LONG_PARAMETER}", type=float, default=DEFAULT_SESSION_TTL,
            help=f"time to live (ttl) in seconds of the session that will be created to hold the lock. Must be between "
                 f"{MIN_LOCK_TIMEOUT_IN_SECONDS}s and {MAX_LOCK_TIMEOUT_IN_SECONDS}s (inclusive). If set to "
                 f"{NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE}, the session will not expire")
        subparser.add_argument(
            f"--{NON_BLOCKING_LONG_PARAMETER}", action="store_true",
            default=DEFAULT_NON_BLOCKING, help="do not block if cannot lock straight away")
        subparser.add_argument(
            f"--{TIMEOUT_LONG_PARAMETER}", default=DEFAULT_TIMEOUT, type=float,
            help="give up trying to acquire the key after this many seconds (where 0 is never)")
        subparser.add_argument(
            f"--{METADATA_LONG_PARAMETER}", default=DEFAULT_METADATA, type=str, action=_ParseJsonAction,
            help="additional metadata to add to the lock information (will be converted to JSON)")
        subparser.add_argument(
            f"--{ON_BEFORE_LOCK_LONG_PARAMETER}", default=[], type=str, nargs="+", action="append",
            help="path to executable that is to be called before an attempt is made to acquire a lock, where the lock "
                 "key is passed as the first argument. Any failures of this executable are ignored")
        subparser.add_argument(
            f"--{ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER}", default=[], type=str, nargs="+", action="append",
            help="path to executable that is to be called after an attempt has been made to acquire a lock but failed "
                 "due to the lock already been taken, where the lock key is passed as the first argument. Any failures "
                 "of this executable are ignored")
        subparser.add_argument(
            f"-{LOCK_POLL_INTERVAL_SHORT_PARAMETER}", default=DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1), type=float,
            help="number of seconds between polls to acquire a locked lock")

    # XXX: probably a better way of iterating subparsers on `subparsers`
    for subparser in [unlock_subparser, lock_subparser, lock_and_execute_subparser]:
        subparser.add_argument(
            KEY_PARAMETER, type=str, help="the lock identifier")

    lock_and_execute_subparser.add_argument(
        EXECUTABLE_PARAMETER, type=str, help="to execute in shell")

    return parser


_argument_parser = _create_parser()


def parse_cli_configuration(arguments: List[str]) -> CliConfiguration:
    """
    Parses the configuration passed in via command line arguments.
    :param arguments: CLI arguments
    :return: the configuration
    """
    try:
        parsed_arguments = {x.replace("_", "-"): y for x, y in vars(_argument_parser.parse_args(arguments)).items()}
    except SystemExit as e:
        if e.code == SUCCESS_EXIT_CODE:
            raise e
        raise InvalidCliArgumentError() from e

    parsed_action = parsed_arguments[ACTION_CLI_PARAMETER_ACCESS]
    if parsed_action is None:
        _argument_parser.print_help()
        exit(INVALID_CLI_ARGUMENT_EXIT_CODE)
    action = Action(parsed_action)

    session_ttl = parsed_arguments.get(SESSION_TTL_LONG_PARAMETER, None)
    if session_ttl == NO_EXPIRY_SESSION_TTL_CLI_PARAMETER_VALUE:
        session_ttl = None

    shared_parameters = dict(
        key=parsed_arguments[KEY_PARAMETER],
        log_verbosity=_get_verbosity(parsed_arguments), session_ttl=session_ttl)

    if action == Action.UNLOCK:
        return CliUnlockConfiguration(
            **shared_parameters,
            regex_key_enabled=parsed_arguments.get(REGEX_KEY_ENABLED_SHORT_PARAMETER, DEFAULT_REGEX_KEY_ENABLED))
    else:
        parameters = dict(
            **shared_parameters,
            non_blocking=parsed_arguments.get(NON_BLOCKING_LONG_PARAMETER, DEFAULT_NON_BLOCKING),
            timeout=parsed_arguments.get(TIMEOUT_LONG_PARAMETER, DEFAULT_TIMEOUT),
            metadata=parsed_arguments.get(METADATA_LONG_PARAMETER, DEFAULT_METADATA),
            on_before_locked_executables=list(itertools.chain(*parsed_arguments.get(
                ON_BEFORE_LOCK_LONG_PARAMETER, []))),
            on_lock_already_locked_executables=list(itertools.chain(*parsed_arguments.get(
                ON_LOCK_ALREADY_LOCKED_LONG_PARAMETER, []))),
            lock_poll_interval=parsed_arguments.get(
                LOCK_POLL_INTERVAL_SHORT_PARAMETER, DEFAULT_LOCK_POLL_INTERVAL_GENERATOR(1)))

        if action == Action.LOCK:
            return CliLockConfiguration(**parameters)
        else:
            return CliLockAndExecuteConfiguration(
                **parameters,
                executable=parsed_arguments[EXECUTABLE_PARAMETER])


def _get_verbosity(parsed_arguments: Dict) -> int:
    """
    Gets the verbosity level from the parsed arguments.
    :param parsed_arguments: the parsed arguments
    :return: the verbosity level implied
    """
    verbosity = DEFAULT_LOG_VERBOSITY - (int(parsed_arguments[VERBOSE_SHORT_PARAMETER]) * 10)
    if verbosity < 10:
        raise InvalidCliArgumentError("Cannot provide any further logging - reduce log verbosity")
    assert verbosity <= logging.CRITICAL
    return verbosity


def _generate_event_listener_caller(executables: List[str]) -> LockEventListener:
    """
    TODO
    :param executables:
    :return:
    """
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


def _acquire_lock(lock_manager: ConsulLockManager, configuration: CliLockConfiguration) \
        -> Optional[ConnectedConsulLockInformation]:
    """
    TODO
    :param lock_manager:
    :param configuration:
    :return:
    """
    event_listeners: LockEventListener = {}
    if configuration.on_before_locked_executables is not None:
        event_listeners["on_before_lock"] = _generate_event_listener_caller(
            configuration.on_before_locked_executables)
    if configuration.on_lock_already_locked_executables is not None:
        event_listeners["on_lock_already_locked"] = _generate_event_listener_caller(
            configuration.on_lock_already_locked_executables)

    try:
        return lock_manager.acquire(
            key=configuration.key, blocking=not configuration.non_blocking,
            timeout=configuration.timeout, metadata=configuration.metadata, **event_listeners,
            lock_poll_interval_generator=lambda i: configuration.lock_poll_interval)
    except LockAcquireTimeoutError as e:
        logger.debug(e)
        logger.error(f"Timed out whilst waiting to acquire lock: {configuration.key}")
        print(json.dumps(None))
        exit(LOCK_ACQUIRE_TIMEOUT_EXIT_CODE)


def _acquire_lock_and_execute(lock_manager: ConsulLockManager, configuration: CliLockAndExecuteConfiguration):
    """
    Executes whilst holding a lock, exiting after the execute returns with the executables return code.
    :param lock_manager: the lock manager
    :param configuration: the configuration
    """
    lock = _acquire_lock(lock_manager, configuration)
    if lock is None:
        exit(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE)
    return_code, _, _ = lock_manager.execute_with_lock(configuration.executable, lock)
    exit(return_code)


def _acquire_lock_and_exit(lock_manager: ConsulLockManager, configuration: CliLockConfiguration):
    """
    Locks a lock then exits.
    :param lock_manager: the lock manager
    :param configuration: the configuration required to lock the lock
    """
    lock = _acquire_lock(lock_manager, configuration)
    print(json.dumps(lock, cls=ConsulLockInformationJSONEncoder, sort_keys=True))

    if lock is None:
        logger.error(f"Unable to acquire lock: {configuration.key}")
        exit(UNABLE_TO_ACQUIRE_LOCK_EXIT_CODE)

    exit(SUCCESS_EXIT_CODE)


def _release_lock(lock_manager: ConsulLockManager, configuration: CliUnlockConfiguration):
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
    cli_configuration: CliConfiguration
    try:
        cli_configuration = parse_cli_configuration(cli_arguments)
    except InvalidCliArgumentError as e:
        logger.error(e)
        exit(INVALID_CLI_ARGUMENT_EXIT_CODE)
    except SystemExit as e:
        exit(e.code)

    if cli_configuration.log_verbosity:
        logging.getLogger(PACKAGE_NAME).setLevel(cli_configuration.log_verbosity)

    consul_configuration: ConsulConfiguration
    try:
        consul_configuration = get_consul_configuration_from_environment()
    except KeyError as e:
        logger.error(f"Cannot connect to Consul - the environment variable {e.args[0]} must be set")
        exit(MISSING_REQUIRED_ENVIRONMENT_VARIABLE_EXIT_CODE)
    except InvalidEnvironmentVariableError as e:
        logger.error(e)
        exit(INVALID_ENVIRONMENT_VARIABLE_EXIT_CODE)

    lock_manager: ConsulLockManager
    try:
        lock_manager = ConsulLockManager(
            consul_configuration=consul_configuration, session_ttl_in_seconds=cli_configuration.session_ttl)
    except InvalidSessionTtlValueError as e:
        logger.error(e)
        exit(INVALID_SESSION_TTL_EXIT_CODE)

    try:
        {
            CliLockConfiguration: _acquire_lock_and_exit,
            CliLockAndExecuteConfiguration: _acquire_lock_and_execute,
            CliUnlockConfiguration: _release_lock
        }[type(cli_configuration)](lock_manager, cli_configuration)
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
