import os
import unittest
from copy import deepcopy

from capturewrap import CaptureWrapBuilder
from consullock.configuration import DEFAULT_CONSUL_PORT, CONSUL_HOST_ENVIRONMENT_VARIABLE, \
    CONSUL_PORT_ENVIRONMENT_VARIABLE
from useintest.predefined.consul import ConsulServiceController, ConsulDockerisedService

TEST_KEY = "hello"
TEST_VALUE = "world"

all_capture_builder = CaptureWrapBuilder(True, True, True)


class _EnvironmentPreservingTest(unittest.TestCase):
    """
    Tests for ConsulLock.
    """
    def setUp(self):
        self._consul_service_controller = ConsulServiceController()
        self._env_cache = deepcopy(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_cache)


def set_consul_env(service: ConsulDockerisedService):
    """
    TODO
    :param service:
    :return:
    """
    os.environ[CONSUL_HOST_ENVIRONMENT_VARIABLE] = service.host
    os.environ[CONSUL_PORT_ENVIRONMENT_VARIABLE] = str(service.ports[DEFAULT_CONSUL_PORT])

