from consul import Consul

from consullock.configuration import ConsulConfiguration


def create_consul_client(consul_configuration: ConsulConfiguration) -> Consul:
    """
    Creates a Consul client using the given configuration.
    :param consul_configuration: the configuration to use to create the client
    :return: the created client
    """
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

    return consul_client
