from collections import namedtuple
from http import HTTPStatus

from pytest import fixture

from api.errors import INVALID_ARGUMENT
from tests.unit.mock_data_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from .utils import get_headers

WrongCall = namedtuple('WrongCall', ('endpoint', 'payload', 'message'))


def wrong_calls():
    yield WrongCall(
        '/tiles/tile',
        {'tile_id': 'some_value'},
        "Invalid JSON payload received. "
        "{'tile-id': ['Missing data for required field.'], "
        "'tile_id': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile',
        {'tile-id': ''},
        "Invalid JSON payload received. "
        "{'tile-id': ['Field may not be blank.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile_id': 'some_value', 'period': 'some_period'},
        "Invalid JSON payload received. "
        "{'tile-id': ['Missing data for required field.'], "
        "'tile_id': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile-id': '', 'period': 'some_period'},
        "Invalid JSON payload received. "
        "{'tile-id': ['Field may not be blank.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile-id': 'some_value', 'not_period': 'some_period'},
        "Invalid JSON payload received. "
        "{'period': ['Missing data for required field.'], "
        "'not_period': ['Unknown field.']}"
    )
    yield WrongCall(
        '/tiles/tile-data',
        {'tile-id': 'some_value', 'period': ''},
        "Invalid JSON payload received. "
        "{'period': ['Field may not be blank.']}"
    )


@fixture(
    scope='module',
    params=wrong_calls(),
    ids=lambda wrong_payload: f'{wrong_payload.endpoint}, '
                              f'{wrong_payload.payload}'
)
def wrong_call(request):
    return request.param


@fixture(scope='module')
def invalid_argument_expected_payload():
    def _make_message(message):
        return {
            'errors': [{
                'code': INVALID_ARGUMENT,
                'message': message,
                'type': 'fatal'
            }]
        }

    return _make_message


def test_dashboard_call_with_wrong_payload(wrong_call, client, valid_jwt,
                                           mock_request, mock_response_data,
                                           invalid_argument_expected_payload):

    mock_request.return_value = mock_response_data(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(
        path=wrong_call.endpoint,
        headers=get_headers(valid_jwt()),
        json=wrong_call.payload
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_argument_expected_payload(
        wrong_call.message
    )


def routes():
    yield '/tiles'
    yield '/tiles/tile'
    yield '/tiles/tile-data'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_dashboard_call_success(
        route, client, valid_jwt, mock_request, mock_response_data
):
    mock_request.return_value = mock_response_data(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(route, headers=get_headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
