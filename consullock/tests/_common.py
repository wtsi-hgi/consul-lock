from contextlib import contextmanager, redirect_stdout, redirect_stderr

import os
from io import StringIO
from typing import Tuple, Any, Callable, Optional

from consul import Consul

from consullock.cli import CONSUL_HOST_ENVIRONMENT_VARIABLE, CONSUL_PORT_ENVIRONMENT_VARIABLE
from consullock.configuration import DEFAULT_CONSUL_PORT
from useintest.services.models import DockerisedService

from useintest.predefined.consul import ConsulServiceController

TEST_KEY = "hello"
TEST_VALUE = "world"


@contextmanager
def start_consul(controller: ConsulServiceController) -> Consul:
    """
    Start Consul, returning a client to it.
    :param controller: a Consul controller
    :return: client connected to the running Consul server
    """
    with controller.start_service() as service:
        consul_client = Consul(service.host, service.ports[DEFAULT_CONSUL_PORT])
        yield consul_client


def set_consul_env(service: DockerisedService):
    """
    TODO
    :param service:
    :return:
    """
    os.environ[CONSUL_HOST_ENVIRONMENT_VARIABLE] = service.host
    os.environ[CONSUL_PORT_ENVIRONMENT_VARIABLE] = str(service.ports[DEFAULT_CONSUL_PORT])


def capture_stdout(callable: Callable, *args, **kwargs) -> Tuple[Optional[Any], str, Optional[Exception]]:
    """
    TODO
    :return:
    """
    stream = StringIO()
    exception = None
    with redirect_stdout(stream):
        try:
            return_value = callable(*args, **kwargs)
        except BaseException as e:
            exception = e
            return_value = None
    return return_value, stream.getvalue(), exception


def capture_stdout_and_stderr(callable: Callable, *args, **kwargs) -> Tuple[Optional[Any], str, str, Optional[Exception]]:
    """
    TODO
    :param callable:
    :param args:
    :param kwargs:
    :return:
    """
    stream = StringIO()
    with redirect_stderr(stream):
        return_value, stdout, exception = capture_stdout(callable, *args, **kwargs)
    return return_value, stdout, stream.getvalue(), exception

