from flask import Blueprint

from api.schemas import DashboardTileSchema, DashboardTileDataSchema
from api.utils import jsonify_data, get_api_key, get_json

dashboard_api = Blueprint('dashboard', __name__)


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    _ = get_api_key()
    return jsonify_data([])


@dashboard_api.route('/tiles/tile', methods=['POST'])
def tile():
    _ = get_api_key()
    _ = get_json(DashboardTileSchema())
    return jsonify_data({})


@dashboard_api.route('/tiles/tile-data', methods=['POST'])
def tile_data():
    _ = get_api_key()
    _ = get_json(DashboardTileDataSchema())
    return jsonify_data({})
