from collections import namedtuple
from http import HTTPStatus

from pytest import fixture

from api.schemas import OBSERVABLE_TYPE_CHOICES
from .utils import get_headers, get_from_isoformat
from tests.unit.mock_data_for_tests import (
    AUTOFOCUS_IP_RESPONSE_MOCK,
    AUTOFOCUS_IPV6_RESPONSE_MOCK,
    AUTOFOCUS_DOMAIN_RESPONSE_MOCK,
    AUTOFOCUS_URL_RESPONSE_MOCK,
    AUTOFOCUS_SHA256_RESPONSE_MOCK,
    INTEGRATION_IP_RESPONSE_MOCK,
    INTEGRATION_URL_RESPONSE_MOCK,
    INTEGRATION_IPV6_RESPONSE_MOCK,
    INTEGRATION_DOMAIN_RESPONSE_MOCK,
    INTEGRATION_SHA256_RESPONSE_MOCK,
    ENTITY_LIFETIME_MOCK
)
from api.errors import (
    INVALID_ARGUMENT
)


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@fixture(scope='module')
def invalid_json_type():
    return [{'type': 'strange', 'value': 'cisco.com'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        route, client, valid_jwt, invalid_json_value,
        exception_expected_payload
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        INVALID_ARGUMENT,
        "Invalid JSON payload received. "
        "{0: {'value': ['Field may not be blank.']}}"
    )


def test_enrich_call_with_valid_jwt_but_invalid_json_type(
        route, client, valid_jwt, invalid_json_type,
        exception_expected_payload
):
    allowed_fields = ", ".join(map(repr, OBSERVABLE_TYPE_CHOICES))
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_type)
    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        INVALID_ARGUMENT,
        'Invalid JSON payload received. '
        '{0: {\'type\': ["Must be one of: ' + allowed_fields + '."]}}'
    )


Call = namedtuple('Call', ('json',
                           'autofocus_mock_response',
                           'integration_mock_response'))


def calls():
    yield Call(
        [{'type': 'ip', 'value': '103.110.84.196'}],
        AUTOFOCUS_IP_RESPONSE_MOCK, INTEGRATION_IP_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'ipv6', 'value': '2001:db8:85a3:8d3:1319:8a2e:370:7348'}],
        AUTOFOCUS_IPV6_RESPONSE_MOCK, INTEGRATION_IPV6_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'domain', 'value': 'cisco.com'}],
        AUTOFOCUS_DOMAIN_RESPONSE_MOCK, INTEGRATION_DOMAIN_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'url', 'value': 'http://0win365.com/wp-admin/sites/'}],
        AUTOFOCUS_URL_RESPONSE_MOCK, INTEGRATION_URL_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'sha256',
          'value': '7fa2c54d7dabb0503d75bdd13cc4d6a'
                   '6520516a990fb7879ae052bad9520763b'}],
        AUTOFOCUS_SHA256_RESPONSE_MOCK, INTEGRATION_SHA256_RESPONSE_MOCK
    )


@fixture(scope='module', params=calls(), ids=lambda call: f'{call.json}')
def call(request):
    return request.param


def assert_verdicts(response, call, test_data):
    valid_time = response['data']['verdicts']['docs'][0].pop('valid_time')
    if call.json[0]['type'] == 'sha256':
        assert valid_time['end_time'] == 'indefinite'
    else:
        start_time = get_from_isoformat(valid_time['start_time'])
        end_time = get_from_isoformat(valid_time['end_time'])
        assert end_time - start_time == ENTITY_LIFETIME_MOCK

    assert response == test_data


def test_enrich_call_success(
        route, call, client, valid_jwt,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.OK,
        payload=call.autofocus_mock_response
    )
    response = client.post(route, headers=get_headers(valid_jwt),
                           json=call.json)
    assert response.status_code == HTTPStatus.OK

    response = response.json
    if route == '/deliberate/observables':
        assert_verdicts(response, call, call.integration_mock_response[route])
