import os

from useintest.predefined.consul import ConsulDockerisedService

from consullock.configuration import DEFAULT_CONSUL_PORT, CONSUL_ADDRESS_ENVIRONMENT_VARIABLE
from consullock.managers import KEY_DIRECTORY_SEPARATOR

KEY_DIRECTORY = "my"
KEY_1 = f"{KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}hello"
KEY_2 = f"{KEY_DIRECTORY}{KEY_DIRECTORY_SEPARATOR}other"
KEYS_1 = [f"{KEY_1}{KEY_DIRECTORY_SEPARATOR}{i}" for i in range(5)]
KEYS_1_REGEX = f"{KEY_DIRECTORY_SEPARATOR.join(KEYS_1[0].split(KEY_DIRECTORY_SEPARATOR)[0:-1])}" \
             f"{KEY_DIRECTORY_SEPARATOR}[0-9]+"
KEYS_2 = [f"other{KEY_DIRECTORY}other", f"{KEY_1}{KEY_DIRECTORY_SEPARATOR}1a", f"{KEY_1}0"]

VALUE_1 = "world"
VALUE_2 = "example"

ERROR_EXIT_CODE = 33

METADATA = {"testString": "metadata", "testFloat": 3.1415926535}


def set_consul_env(service: ConsulDockerisedService):
    """
    Sets environment variables such that communication to Consul is possible using the information in the environment.
    :param service: Dockerized Consul service that is to be connected to
    """
    os.environ[CONSUL_ADDRESS_ENVIRONMENT_VARIABLE] = f"{service.host}:{service.ports[DEFAULT_CONSUL_PORT]}"
