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
    INVALID_ARGUMENT,
    SERVER_ERROR
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


Call = namedtuple('Call', ('json', 'message',
                           'autofocus_mock_response',
                           'integration_mock_response'))


def valid_calls():
    yield Call(
        [{'type': 'ip', 'value': '103.110.84.196'}], 'ip',
        AUTOFOCUS_IP_RESPONSE_MOCK, INTEGRATION_IP_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'ipv6', 'value': '2001:db8:85a3:8d3:1319:8a2e:370:7348'}],
        'ipv6', AUTOFOCUS_IPV6_RESPONSE_MOCK, INTEGRATION_IPV6_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'domain', 'value': 'cisco.com'}], 'domain',
        AUTOFOCUS_DOMAIN_RESPONSE_MOCK, INTEGRATION_DOMAIN_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'url', 'value': 'http://0win365.com/wp-admin/sites/'}],
        'url', AUTOFOCUS_URL_RESPONSE_MOCK, INTEGRATION_URL_RESPONSE_MOCK
    )
    yield Call(
        [{'type': 'sha256',
          'value': '7fa2c54d7dabb0503d75bdd13cc4d6a'
                   '6520516a990fb7879ae052bad9520763b'}], 'sha256',
        AUTOFOCUS_SHA256_RESPONSE_MOCK, INTEGRATION_SHA256_RESPONSE_MOCK
    )
    yield Call(
        [
            {'type': 'ip', 'value': '103.110.84.196'},
            {'type': 'ip', 'value': '103.110.84.196'}
        ], 'two same observables',
        AUTOFOCUS_IP_RESPONSE_MOCK, INTEGRATION_IP_RESPONSE_MOCK
    )
    yield Call(
        [
            {'type': 'ip', 'value': '103.110.84.196'},
            {'type': 'md5', 'value': 'm3n4cv53m45c345m34c5m3c5'}
        ], 'unsupported type',
        AUTOFOCUS_IP_RESPONSE_MOCK, INTEGRATION_IP_RESPONSE_MOCK
    )


@fixture(
    scope='module', params=valid_calls(), ids=lambda call: f'{call.message}'
)
def valid_call(request):
    return request.param


def assert_valid_time(valid_time, type_):
    if type_ == 'sha256':
        assert valid_time['end_time'] == '2525-01-01T00:00:00Z'
    else:
        start_time = get_from_isoformat(valid_time['start_time'])
        end_time = get_from_isoformat(valid_time['end_time'])
        assert end_time - start_time == ENTITY_LIFETIME_MOCK


def assert_deliberate_observables(response, call, test_data):
    valid_time = response['data']['verdicts']['docs'][0].pop('valid_time')
    assert_valid_time(valid_time, call.json[0]['type'])
    assert response == test_data


def assert_observe_observables(response, call, test_data):
    verdict = response['data']['verdicts']
    judgement = response['data']['judgements']
    assert_valid_time(
        verdict['docs'][0].pop('valid_time'), call.json[0]['type']
    )
    assert_valid_time(
        judgement['docs'][0].pop('valid_time'), call.json[0]['type']
    )
    assert verdict['docs'][0].pop('judgement_id') == \
           judgement['docs'][0].pop('id')
    assert response == test_data


def assert_refer_observables(response, test_data):
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
        assert_deliberate_observables(
            response, valid_call, valid_call.integration_mock_response[route]
        )
    elif route == '/observe/observables':
        assert_observe_observables(
            response, valid_call, valid_call.integration_mock_response[route]
        )
    elif route == '/refer/observables':
        assert_refer_observables(
            response, valid_call.integration_mock_response[route]
        )


@fixture(scope='module')
def observable_404():
    return [{'type': 'sha256', 'value': 'anaptanium'}]


def test_enrich_call_with_404_observable(
        route, client, valid_jwt, observable_404,
        mock_request_to_autofocus, mock_autofocus_response_data,

):
    if route != '/refer/observables':
        mock_request_to_autofocus.return_value = mock_autofocus_response_data(
            status_code=HTTPStatus.NOT_FOUND
        )
        response = client.post(route, headers=get_headers(valid_jwt),
                               json=observable_404)

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {}}


def test_call_with_response_data_error(
        route, client, valid_jwt, valid_json, exception_expected_payload,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    if route != '/refer/observables':
        mock_request_to_autofocus.return_value = mock_autofocus_response_data(
            status_code=HTTPStatus.OK,
            payload={'abracadabra': 'data'}
        )
        response = client.post(route, headers=get_headers(valid_jwt),
                               json=valid_json)
        assert response.status_code == HTTPStatus.OK
        assert response.json == exception_expected_payload(
            SERVER_ERROR,
            'The data structure of AutoFocus has changed. The '
            'module is broken.'
        )
