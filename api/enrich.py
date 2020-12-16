from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial

from flask import Blueprint, g, current_app

from api.client import ApiClient
from api.entities import Entity
from api.schemas import ObservableSchema
from api.utils import (
    get_json,
    get_api_key,
    jsonify_data,
    filter_observables,
    get_workers
)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    api_key = get_api_key()
    status_mapping = current_app.config['STATUS_MAPPING']
    entity_lifetime = current_app.config['ENTITY_LIFETIME']
    observables = filter_observables(get_observables())

    if not observables:
        return jsonify_data()

    g.verdicts = []
    client = ApiClient(
        api_key=api_key,
        base_url=current_app.config['AUTOFOCUS_API_URL'],
        user_agent=current_app.config['USER_AGENT']
    )

    with ThreadPoolExecutor(
            max_workers=get_workers(len(observables))
    ) as executor:
        entities = executor.map(
            lambda observable: Entity(
                response=client.get_tic_indicator_data(observable),
                observable=observable,
                status_mapping=status_mapping,
                entity_lifetime=entity_lifetime
            ), observables)

    for entity in entities:
        if entity.response:
            g.verdicts.append(entity.get_verdict())

    return jsonify_data()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    _ = get_api_key()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_api_key()
    _ = get_observables()
    return jsonify_data([])
