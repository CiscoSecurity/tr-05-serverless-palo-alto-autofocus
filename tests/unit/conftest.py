from http import HTTPStatus
from unittest.mock import patch, MagicMock

import jwt
from pytest import fixture

from app import app
from tests.unit.mock_data_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            limit=100,
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


@fixture(scope='function')
def mock_request():
    with patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='function')
def mock_response_data():
    def _set_data(status_code=None, payload=None):
        mock_data = MagicMock()

        mock_data.status_code = status_code if status_code else HTTPStatus.OK

        if payload:
            mock_data.json = lambda: payload

        return mock_data
    return _set_data


@fixture(scope='module')
def exception_expected_payload():
    def _make_message(code, message):
        return {
            'errors': [{
                'code': code,
                'message': message,
                'type': 'fatal'
            }]
        }

    return _make_message
