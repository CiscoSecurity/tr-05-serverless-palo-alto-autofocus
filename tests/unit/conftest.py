from datetime import datetime
from http import HTTPStatus
from unittest.mock import patch, MagicMock

from authlib.jose import jwt
from pytest import fixture

from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'key': 'some_key'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='function')
def mock_request_to_autofocus():
    with patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='function')
def mock_autofocus_response_data():
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
