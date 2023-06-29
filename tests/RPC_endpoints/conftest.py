from pytest import fixture


def pytest_addoption(parser):
    parser.addoption("--network-url", action="store")
    parser.addoption("--network-name", action="store")
    parser.addoption("--network-version", action="store")
    parser.addoption("--chain-id", action="store")
    parser.addoption("--node-mode", action="store")
    parser.addoption("--node-number", action="store")


@fixture()
def network_url(request):
    return request.config.getoption("--network-url")


@fixture()
def network_name(request):
    return request.config.getoption("--network-name")


@fixture()
def network_version(request):
    return request.config.getoption("--network-version")


@fixture()
def chain_id(request):
    return request.config.getoption("--chain-id")


@fixture()
def node_mode(request):
    return request.config.getoption("--node-mode")


@fixture()
def node_number(request):
    return request.config.getoption("--node-number")
