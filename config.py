import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    AUTOFOCUS_API_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0'

    HEALTH_OBSERVABLE = {'type': 'domain', 'value': 'cisco.com'}

    SUPPORTED_TYPES = ('ip', 'ipv6', 'domain', 'url', 'sha256')

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_DEFAULT
