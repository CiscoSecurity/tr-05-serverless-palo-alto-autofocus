from http import HTTPStatus

import requests
from requests.exceptions import InvalidHeader

from api.utils import catch_ssl_error
from api.errors import (
    AuthorizationError,
    AutofocusNotFoundError,
    AutofocusTooManyRequestsError,
    AutofocusServerError,
    TRFormattedError
)


class ApiClient:
    health_test_observable = None

    def __init__(self, api_key, base_url, user_agent=None):
        self.api_key = api_key
        self.base_url = base_url
        self.user_agent = user_agent

    @catch_ssl_error
    def get_autofocus_data(self, observable, endpoint):
        try:
            response = requests.get(
                url=self._url_for(endpoint),
                headers=self._get_headers(),
                params=self._get_tic_params(observable)
            )
        except (UnicodeEncodeError, InvalidHeader):
            raise AuthorizationError
        return self._get_response_data(response, observable)

    def get_tic_indicator_data(self, observable):
        return self.get_autofocus_data(observable, 'tic')

    def _url_for(self, endpoint):
        return f'{self.base_url}/{endpoint}'

    @staticmethod
    def _get_tic_params(observable, tags='true'):
        indicator_type_mapping = {
            'ip': 'ipv4_address',
            'ipv6': 'ipv6_address',
            'domain': 'domain',
            'url': 'url',
            'sha256': 'filehash'
        }
        return {
            'indicatorType': indicator_type_mapping[observable['type']],
            'indicatorValue': observable['value'],
            'includeTags': tags
        }

    def _get_headers(self):
        headers = {
            'apiKey': self.api_key,
            'Content-Type': 'application/json',
        }
        if self.user_agent:
            headers.update({'User-Agent': self.user_agent})
        return headers

    def _get_response_data(self, response, observable):
        expected_errors = {
            HTTPStatus.UNAUTHORIZED: lambda: AuthorizationError(),
            HTTPStatus.TOO_MANY_REQUESTS:
                lambda: AutofocusTooManyRequestsError(),
            HTTPStatus.CONFLICT: lambda: AuthorizationError(response.text)
        }

        if response.status_code == HTTPStatus.OK:
            return response.json()
        elif response.status_code >= 500:
            raise AutofocusServerError
        elif response.status_code == HTTPStatus.NOT_FOUND:
            # in some cases, when AutoFocus can't find observable,
            # it returns 404
            if observable != self.health_test_observable:
                return {}
            else:
                raise AutofocusNotFoundError

        elif response.status_code in expected_errors:
            raise expected_errors[response.status_code]()
        else:
            raise TRFormattedError(
                HTTPStatus(response.status_code).phrase,
                f'Unexpected response from AutoFocus: {response.text}'
            )
