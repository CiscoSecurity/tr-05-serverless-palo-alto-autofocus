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
        mock_request, mock_response_data, test_keys_and_token
):
    mock_request.side_effect = (
        mock_response_data(payload=test_keys_and_token["jwks"]),
        mock_response_data()
    )

    response = client.post(route, headers=get_headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
