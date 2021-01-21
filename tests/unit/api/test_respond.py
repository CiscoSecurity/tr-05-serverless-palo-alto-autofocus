from collections import namedtuple
from http import HTTPStatus

from pytest import fixture

from api.errors import INVALID_ARGUMENT
from .utils import get_headers
from tests.unit.mock_data_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT

InvalidJsonCall = namedtuple(
    'InvalidJsonCall', ('route', 'json', 'message_template', 'text')
)

error_message_template = {
    'observable_name': "Invalid JSON payload received. "
                       "{0: {'%s': ['Missing data for required field.'], "
                       "'': ['Unknown field.']}}",
    'observable_value': "Invalid JSON payload received. "
                        "{0: {'%s': ['Field may not be blank.']}}",
    'trigger_value': "Invalid JSON payload received. {'%s': ['Field "
                     "may not be blank.']}",
    'trigger_name': "Invalid JSON payload received. {'%s': "
                    "['Missing data for required field.']}"
}


def invalid_json_calls():
    yield InvalidJsonCall('/respond/observables',
                          [{'type': 'ip', 'value': ''}],
                          error_message_template['observable_value'], 'value')
    yield InvalidJsonCall('/respond/observables',
                          [{'type': '', 'value': 'some_value'}],
                          error_message_template['observable_value'], 'type')
    yield InvalidJsonCall('/respond/observables',
                          [{'': 'ip', 'value': '1.1.1.1'}],
                          error_message_template['observable_name'], 'type')
    yield InvalidJsonCall('/respond/observables',
                          [{'type': 'ip', '': 'some_value'}],
                          error_message_template['observable_name'], 'value')
    yield InvalidJsonCall('/respond/trigger',
                          {'action-id': '',
                           'observable_type': 'domain',
                           'observable_value': 'cisco.com'},
                          error_message_template['trigger_value'],
                          'action-id')
    yield InvalidJsonCall('/respond/trigger',
                          {'action-id': 'some_action_id',
                           'observable_type': '',
                           'observable_value': 'cisco.com'},
                          error_message_template['trigger_value'],
                          'observable_type')
    yield InvalidJsonCall('/respond/trigger',
                          {'action-id': 'some_action_id',
                           'observable_type': 'domain',
                           'observable_value': ''},
                          error_message_template['trigger_value'],
                          'observable_value')
    yield InvalidJsonCall('/respond/trigger',
                          {'': 'some_action_id',
                           'observable_type': 'domain',
                           'observable_value': 'cisco.com'},
                          error_message_template['trigger_name'],
                          'action-id')
    yield InvalidJsonCall('/respond/trigger',
                          {'action-id': 'some_action_id',
                           '': 'domain',
                           'observable_value': 'cisco.com'},
                          error_message_template['trigger_name'],
                          'observable_type')
    yield InvalidJsonCall('/respond/trigger',
                          {'action-id': 'some_action_id',
                           'observable_type': 'domain',
                           '': 'cisco.com'},
                          error_message_template['trigger_name'],
                          'observable_value')


@fixture(scope='module', params=invalid_json_calls(),
         ids=lambda call: f'{call.route} {call.json}')
def invalid_json_call(request):
    return request.param


def test_respond_call_with_valid_jwt_but_invalid_json(
        client, valid_jwt, invalid_json_call,
        mock_request, mock_response_data,
        exception_expected_payload
):
    mock_request.return_value = mock_response_data(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(invalid_json_call.route,
                           headers=get_headers(valid_jwt()),
                           json=invalid_json_call.json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        INVALID_ARGUMENT,
        invalid_json_call.message_template % invalid_json_call.text
    )


def routes():
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'domain', 'value': 'cisco.com'}]

    if route.endswith('/trigger'):
        return {'action-id': 'valid-action-id',
                'observable_type': 'domain',
                'observable_value': 'cisco.com'}


def test_respond_call_success(
        route, client, valid_jwt, valid_json, mock_request, mock_response_data
):
    mock_request.return_value = mock_response_data(
        payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )

    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
