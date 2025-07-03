from datetime import datetime


def get_headers(jwt, auth_type='Bearer'):
    return {'Authorization': f'{auth_type} {jwt}'}


def get_from_isoformat(time):
    return datetime.fromisoformat(time[0:-1])
