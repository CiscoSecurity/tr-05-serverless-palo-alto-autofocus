from http import HTTPStatus

from pytest import fixture

from .utils import get_headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(
        route, client, valid_jwt,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data()
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
