import os

from capturewrap import CaptureWrapBuilder
from useintest.predefined.consul import ConsulDockerisedService

from consullock.configuration import DEFAULT_CONSUL_PORT, CONSUL_ADDRESS_ENVIRONMENT_VARIABLE
from consullock.managers import KEY_DIRECTORY_SEPARATOR

TEST_KEY_DIRECTORY = "my"
TEST_KEY = f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}hello"
TEST_KEY_2 = f"{TEST_KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}other"
TEST_VALUE = "world"

TEST_KEYS = [f"{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}{i}" for i in range(5)]
TEST_KEYS_REGEX = f"{KEY_DIRECTORY_SEPARATOR.join(TEST_KEYS[0].split(KEY_DIRECTORY_SEPARATOR)[0:-1])}" \
                  f"{KEY_DIRECTORY_SEPARATOR}[0-9]+"
TEST_KEYS_2 = [f"other{TEST_KEY_DIRECTORY}other", f"{TEST_KEY}{KEY_DIRECTORY_SEPARATOR}1a", f"{TEST_KEY}0"]

all_capture_builder = CaptureWrapBuilder(True, True, True)


def set_consul_env(service: ConsulDockerisedService):
    """
    Sets environment variables such that communication to Consul is possible using the information in the environment.
    :param service: Dockerized Consul service that is to be connected to
    """
    os.environ[CONSUL_ADDRESS_ENVIRONMENT_VARIABLE] = f"{service.host}:{service.ports[DEFAULT_CONSUL_PORT]}"
