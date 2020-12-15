import os
from datetime import timedelta

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    AUTOFOCUS_API_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0'

    HEALTH_OBSERVABLE = {'type': 'domain', 'value': 'cisco.com'}

    EXPECTED_TYPES = ('ip', 'ipv6', 'domain', 'url', 'sha256')

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
