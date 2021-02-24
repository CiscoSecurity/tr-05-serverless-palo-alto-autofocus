from http import HTTPStatus

from pytest import fixture

from .utils import get_headers
from tests.unit.mock_data_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(
        route, client, valid_jwt,
        mock_request, mock_response_data
):
    mock_request.side_effect = (
        mock_response_data(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        mock_response_data()
    )

    response = client.post(route, headers=get_headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
