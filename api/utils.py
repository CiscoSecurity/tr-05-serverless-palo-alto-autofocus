from os import cpu_count

from authlib.jose import jwt
from authlib.jose.errors import DecodeError, BadSignatureError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError

from api.errors import (
    AuthorizationError,
    InvalidArgumentError,
    AutofocusSSLError
)


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_api_key():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'])['key']
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def format_data(data):
    return {'count': len(data), 'docs': data}


def jsonify_data(data=None):

    if data is not None:
        return jsonify({'data': data})

    result = {'data': {}}

    if g.get('verdicts'):
        result['data']['verdicts'] = format_data(g.verdicts)

    return jsonify(result)


def jsonify_errors(data):
    return jsonify({'errors': [data]})


def catch_ssl_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise AutofocusSSLError(error)
    return wrapper


def remove_duplicates(sequence):
    return [
        el for ind, el in enumerate(sequence) if el not in sequence[ind + 1:]
    ]


def filter_observables(observables):
    expected_types = current_app.config['EXPECTED_TYPES']
    observables = remove_duplicates(observables)
    return list(filter(lambda obs: obs['type'] in expected_types, observables))


def get_workers(required_number):
    return min(required_number, (cpu_count() or 1) * 5) or 1
