import json
from os import cpu_count

import jwt
import requests
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError, ConnectionError, InvalidURL

from api.errors import (
    AuthorizationError,
    InvalidArgumentError,
    AutofocusSSLError
)

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make suer domain in custom_jwks_host '
             'corresponds to your SekureX instance region.')
JWK_HOST_MISSING = ('jwk_host is missing in JWT payload. Make sure '
                    'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


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


def get_public_key(jwks_host, token):
    expected_errors = {
        ConnectionError: WRONG_JWKS_HOST,
        InvalidURL: WRONG_JWKS_HOST,
    }
    try:
        response = requests.get(f"http://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_api_key():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """
    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWK_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }

    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}).get('jwks_host')
        assert jwks_host
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


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
    if g.get('judgements'):
        result['data']['judgements'] = format_data(g.judgements)

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
    supported_types = current_app.config['SUPPORTED_TYPES']
    observables = remove_duplicates(observables)
    return list(
        filter(lambda obs: obs['type'] in supported_types, observables)
    )


def get_workers(required_number):
    return min(required_number, (cpu_count() or 1) * 5) or 1
