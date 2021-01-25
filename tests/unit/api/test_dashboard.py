from http import HTTPStatus

from pytest import fixture


def routes():
    yield '/tiles'
    yield '/tiles/tile'
    yield '/tiles/tile-data'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_dashboard_call_success(route, client):

    response = client.post(route)
    assert response.status_code == HTTPStatus.OK
