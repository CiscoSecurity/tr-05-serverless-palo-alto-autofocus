from flask import Blueprint, current_app

from api.client import ApiClient
from api.utils import get_api_key, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    ApiClient.health_test_observable = current_app.config['HEALTH_OBSERVABLE']
    client = ApiClient(
        api_key=get_api_key(),
        base_url=current_app.config['AUTOFOCUS_API_URL'],
        user_agent=current_app.config['USER_AGENT']
    )

    client.get_tic_indicator_data(current_app.config['HEALTH_OBSERVABLE'])
    return jsonify_data({'status': 'ok'})
