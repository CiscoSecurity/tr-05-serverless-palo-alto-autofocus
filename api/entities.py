from datetime import datetime, timedelta
from urllib.parse import quote_plus, urljoin
from uuid import uuid4

from api.errors import AutofocusDataError

ENTITY_LIFETIME = timedelta(days=7)

SCHEMA_VERSION = '1.0.22'

STATUS_MAPPING = {
    'BENIGN': {
        'disposition': 1,
        'disposition_name': 'Clean'
    },
    'MALWARE': {
        'disposition': 2,
        'disposition_name': 'Malicious'
    },
    'PHISHING': {
        'disposition': 2,
        'disposition_name': 'Malicious'
    },
    'GRAYWARE': {
        'disposition': 3,
        'disposition_name': 'Suspicious'
    }
}

DEFAULT_VERDICT = {'type': 'verdict'}

DEFAULT_JUDGEMENT = {
    'confidence': 'High',
    'priority': 85,
    'schema_version': SCHEMA_VERSION,
    'severity': 'High',
    'source': 'Palo Alto AutoFocus',
    'type': 'judgement',
}

BASE_AUTOFOKUS_URI = (
    'https://autofocus.paloaltonetworks.com/#/search/indicator/'
)

URI_MAPPING = {
    'ip': 'ipv4_address/{value}',
    'ipv6': 'ipv6_address/{value}',
    'domain': 'domain/{value}',
    'url': 'url/{value}/summary',
    'sha256': 'sha256/{value}'
}


class Entity:

    def __init__(self, response, observable):
        self.response = response
        self.observable = observable

    def get_verdict(self):
        disposition, disposition_name = self._get_disposition()

        return {
            'observable': self._get_observable(),
            'disposition': disposition,
            'disposition_name': disposition_name,
            'valid_time': self._get_valid_time(),
            **DEFAULT_VERDICT
        }

    def get_judgement(self):
        disposition, disposition_name = self._get_disposition()

        return {
            'disposition': disposition,
            'disposition_name': disposition_name,
            'id': self._get_transient_id(),
            'observable': self._get_observable(),
            'valid_time': self._get_valid_time(),
            'source_uri': self._get_source_uri(),
            'reason': self._get_reason(),
            **DEFAULT_JUDGEMENT
        }

    def _get_source_uri(self):
        obs_type, value = self.observable['type'], self.observable['value']

        if obs_type == 'url':
            value = quote_plus(value)

        uri = urljoin(
            BASE_AUTOFOKUS_URI, URI_MAPPING[obs_type].format(value=value),
            allow_fragments=False
        )
        return uri

    def _get_reason(self):
        return f'{self._get_autofocus_verdict()} in AutoFocus'

    @staticmethod
    def _get_transient_id():
        return f'transient:judgement-{uuid4()}'

    def _get_autofocus_verdict(self):
        try:
            source = self.response['indicator']['latestPanVerdicts']
            key = 'WF_SAMPLE' if source.get('WF_SAMPLE') else 'PAN_DB'
            return source[key]
        except KeyError:
            raise AutofocusDataError

    def _get_disposition(self):
        autofocus_verdict = self._get_autofocus_verdict()
        return (
            STATUS_MAPPING[autofocus_verdict]['disposition'],
            STATUS_MAPPING[autofocus_verdict]['disposition_name']
        )

    def _get_observable(self):
        return {
            'type': self.observable['type'],
            'value': self.observable['value']
        }

    def _get_valid_time(self):
        start_time = datetime.utcnow()

        if self.observable['type'] == 'sha256':
            end_time = datetime(2525, 1, 1)
        else:
            end_time = start_time + ENTITY_LIFETIME

        return {
            'start_time': self._time_to_ctr_format(start_time),
            'end_time': self._time_to_ctr_format(end_time)
        }

    @staticmethod
    def _time_to_ctr_format(time):
        return time.isoformat() + 'Z'
