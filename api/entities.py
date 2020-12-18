from datetime import datetime, timedelta

ENTITY_LIFETIME = timedelta(days=7)
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


class Entity:

    def __init__(self, response, observable):
        self.response = response
        self.observable = observable

    def get_verdict(self):
        disposition, disposition_name = self._get_disposition()

        return {
            'type': 'verdict',
            'observable': self._get_observable(),
            'disposition': disposition,
            'disposition_name': disposition_name,
            'valid_time': self._get_valid_time(),
        }

    def get_judgement(self):
        pass

    def _get_disposition(self):
        source = self.response['indicator']['latestPanVerdicts']

        key = 'WF_SAMPLE' if source.get('WF_SAMPLE') else 'PAN_DB'

        return (
            STATUS_MAPPING[source[key]]['disposition'],
            STATUS_MAPPING[source[key]]['disposition_name']
        )

    def _get_observable(self):
        return {
            'type': self.observable['type'],
            'value': self.observable['value']
        }

    def _get_valid_time(self):
        start_time = datetime.utcnow()

        if self.observable['type'] == 'sha256':
            return {'start_time': self._time_to_ctr_format(start_time)}

        else:
            end_time = start_time + ENTITY_LIFETIME
            return {
                'start_time': self._time_to_ctr_format(start_time),
                'end_time': self._time_to_ctr_format(end_time)
            }

    @staticmethod
    def _time_to_ctr_format(time):
        return time.isoformat() + 'Z'
