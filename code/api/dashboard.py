from flask import Blueprint

from api.utils import jsonify_data

dashboard_api = Blueprint('dashboard', __name__)


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    # Not implemented
    return jsonify_data([])


@dashboard_api.route('/tiles/tile', methods=['POST'])
def tile():
    # Not implemented
    return jsonify_data({})


@dashboard_api.route('/tiles/tile-data', methods=['POST'])
def tile_data():
    # Not implemented
    return jsonify_data({})
