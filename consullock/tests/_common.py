import os

from capturewrap import CaptureWrapBuilder
from useintest.predefined.consul import ConsulDockerisedService

from consullock.configuration import DEFAULT_CONSUL_PORT, CONSUL_ADDRESS_ENVIRONMENT_VARIABLE

TEST_KEY_DIRECTORY = "my"
TEST_KEY = "hello"
TEST_KEY_2 = "other"
TEST_VALUE = "world"

all_capture_builder = CaptureWrapBuilder(True, True, True)


def set_consul_env(service: ConsulDockerisedService):
    """
    TODO
    :param service:
    :return:
    """
    os.environ[CONSUL_ADDRESS_ENVIRONMENT_VARIABLE] = f"{service.host}:{service.ports[DEFAULT_CONSUL_PORT]}"
