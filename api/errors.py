AUTH_ERROR = 'authorization error'
INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
TOO_MANY_REQUESTS = 'too many requests'
SERVER_ERROR = 'internal error'
SSL_ERROR = 'ssl error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message=None):

        code = AUTH_ERROR

        if message:
            message = f'Authorization failed: {message}'
        else:
            message = "Authorization failed: wrong AutoFocus credentials"

        super().__init__(code, message)


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            INVALID_ARGUMENT,
            f'Invalid JSON payload received. {message}'
        )


class AutofocusNotFoundError(TRFormattedError):
    def __init__(self):
        super().__init__(
            NOT_FOUND,
            'Autofocus not founded.'
        )


class AutofocusTooManyRequestsError(TRFormattedError):
    def __init__(self):
        super().__init__(
            TOO_MANY_REQUESTS,
            'Too many requests have been made to Autofocus. '
            'Please, try again later.'
        )


class AutofocusServerError(TRFormattedError):
    def __init__(self):
        super().__init__(
            SERVER_ERROR,
            'The Autofocus is unavailable. Please, try again later.'
        )


class AutofocusSSLError(TRFormattedError):
    def __init__(self, error):
        message = getattr(
            error.args[0].reason.args[0], 'verify_message', ''
        ) or error.args[0].reason.args[0].args[0]

        super().__init__(
            SSL_ERROR,
            f'Unable to verify SSL certificate: {message}.'
        )
