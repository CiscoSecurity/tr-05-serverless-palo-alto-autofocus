from http import HTTPStatus
from unittest.mock import patch, MagicMock

from tests.utils.crypto import generate_rsa_key_pair
import jwt
from pytest import fixture

from app import app


@fixture(scope="session")
def test_keys_and_token():
    private_pem, jwks, kid = generate_rsa_key_pair()
    wrong_private_pem, wrong_jwks, _ = generate_rsa_key_pair()

    return {
        "private_key": private_pem,
        "jwks": jwks,
        "kid": kid,
        "wrong_private_key": wrong_private_pem,
        "wrong_jwks": wrong_jwks,
    }


@fixture(scope='session')
def client(test_keys_and_token):
    app.rsa_private_key = test_keys_and_token["private_key"]

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
            wrong_structure=False,
            kid=None,
            private_key=None
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_structure:
            payload.pop('key')

        signing_key = private_key or app.rsa_private_key
        signing_kid = kid or "02B1174234C29F8EFB69911438F597FF3FFEE6B7"

        return jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": signing_kid})

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
