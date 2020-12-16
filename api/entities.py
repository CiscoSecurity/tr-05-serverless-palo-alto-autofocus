from datetime import datetime


class Entity:

    def __init__(self, response, observable, status_mapping, entity_lifetime):
        self.response = response
        self.observable = observable
        self.status_mapping = status_mapping
        self.entity_lifetime = entity_lifetime

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
            self.status_mapping[source[key]]['disposition'],
            self.status_mapping[source[key]]['disposition_name']
        )

    def _get_observable(self):
        return {
            'type': self.observable['type'],
            'value': self.observable['value']
        }

    def _get_valid_time(self):
        start_time = datetime.utcnow()

        if self.observable['type'] == 'sha256':
            end_time = 'indefinite'
        else:
            end_time = self._time_to_ctr_format(
                start_time + self.entity_lifetime
            )

        return {
            'start_time': self._time_to_ctr_format(start_time),
            'end_time': self._time_to_ctr_format(end_time)
        }

    @staticmethod
    def _time_to_ctr_format(time):
        return time.isoformat() + 'Z' if isinstance(time, datetime) else time
