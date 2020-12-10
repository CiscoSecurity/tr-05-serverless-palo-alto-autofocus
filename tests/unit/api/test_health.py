from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests.exceptions import SSLError

from .utils import get_headers
from api.errors import (
    AUTH_ERROR,
    AUTOFOCUS_NOT_FOUNDED,
    TOO_MANY_REQUESTS,
    SERVER_ERROR,
    SSL_ERROR
)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_success(
        route, client, valid_jwt,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data()
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}


def test_health_call_with_401(
        route, client, valid_jwt, exception_expected_payload,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.UNAUTHORIZED
    )
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        AUTH_ERROR,
        "Authorization failed: wrong AutoFocus credentials"
    )


def test_health_call_with_404(
        route, client, valid_jwt, exception_expected_payload,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.NOT_FOUND
    )
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        AUTOFOCUS_NOT_FOUNDED,
        "Autofocus not founded."
    )


def test_health_call_with_429(
        route, client, valid_jwt, exception_expected_payload,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.TOO_MANY_REQUESTS
    )
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        TOO_MANY_REQUESTS,
        'Too many requests have been made to Autofocus. '
        'Please, try again later.'
    )


def test_health_call_with_500_plus(
        route, client, valid_jwt, exception_expected_payload,
        mock_request_to_autofocus, mock_autofocus_response_data
):
    mock_request_to_autofocus.return_value = mock_autofocus_response_data(
        status_code=HTTPStatus.SERVICE_UNAVAILABLE
    )
    response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        SERVER_ERROR,
        'The Autofocus is unavailable. Please, try again later.'
    )


def test_health_call_with_ssl_error(
        route, client, valid_jwt, exception_expected_payload
):
    with patch('requests.get') as mock_request:
        mock_request.reason.args.__getitem__().verify_message = \
            'self signed certificate'
        mock_request.side_effect = SSLError(mock_request)
        response = client.post(route, headers=get_headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == exception_expected_payload(
        SSL_ERROR,
        'Unable to verify SSL certificate: self signed '
        'certificate.'
    )
