from collections import namedtuple
from http import HTTPStatus

from pytest import fixture

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


InvalidJsonCall = namedtuple(
    'InvalidJsonCall', ('json', 'message_template', 'text')
)

error_message_template = {
    'name': "Invalid JSON payload received. "
            "{0: {'%s': ['Missing data for required field.'], "
            "'': ['Unknown field.']}}",
    'value': "Invalid JSON payload received. "
             "{0: {'%s': ['Field may not be blank.']}}"
}


def invalid_json_calls():
    yield InvalidJsonCall([{'type': 'ip', 'value': ''}],
                          error_message_template['value'], 'value')
    yield InvalidJsonCall([{'type': '', 'value': 'some_value'}],
                          error_message_template['value'], 'type')
    yield InvalidJsonCall([{'': 'ip', 'value': '1.1.1.1'}],
                          error_message_template['name'], 'type')
    yield InvalidJsonCall([{'type': 'ip', '': 'some_value'}],
                          error_message_template['name'], 'value')


@fixture(scope='module', params=invalid_json_calls(),
         ids=lambda call: f'{call.json}')
def invalid_json_call(request):
    return request.param


def test_enrich_call_with_valid_jwt_but_invalid_json(
        route, client, valid_jwt, invalid_json_call,
        exception_expected_payload
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_call.json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        INVALID_ARGUMENT,
        invalid_json_call.message_template % invalid_json_call.text
    )


Call = namedtuple('Call', ('json',
                           'autofocus_mock_response',
                           'integration_mock_response'))


def valid_calls():
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


@fixture(scope='module', params=valid_calls(), ids=lambda call: f'{call.json}')
def valid_call(request):
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
        route, valid_call, client, valid_jwt,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.OK,
        payload=valid_call.autofocus_mock_response
    )
    response = client.post(route, headers=get_headers(valid_jwt),
                           json=valid_call.json)
    assert response.status_code == HTTPStatus.OK

    response = response.json
    if route == '/deliberate/observables':
        assert_verdicts(
            response, valid_call, valid_call.integration_mock_response[route]
        )
