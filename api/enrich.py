from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial

from flask import Blueprint, g, current_app

from api.client import ApiClient
from api.entities import Entity, SOURCE_NAME
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


def create_entity(response, observable):
    if response:
        return Entity(response=response, observable=observable)


def get_entities():
    api_key = get_api_key()
    observables = filter_observables(get_observables())

    if not observables:
        return {}

    ApiClient.health_test_observable = current_app.config['HEALTH_OBSERVABLE']
    client = ApiClient(
        api_key=api_key,
        base_url=current_app.config['AUTOFOCUS_API_URL'],
        user_agent=current_app.config['USER_AGENT']
    )

    with ThreadPoolExecutor(
            max_workers=get_workers(len(observables))
    ) as executor:
        entities = executor.map(
            lambda observable: create_entity(
                response=client.get_tic_indicator_data(observable),
                observable=observable,
            ), observables)

    return entities


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    entities = get_entities()

    if not entities:
        return jsonify_data()

    g.verdicts = []

    for entity in entities:
        if entity:
            g.verdicts.append(entity.get_verdict())

    return jsonify_data()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    entities = get_entities()

    if not entities:
        return jsonify_data()

    g.verdicts = []
    g.judgements = []

    for entity in entities:
        if entity:
            judgement = entity.get_judgement()
            verdict = entity.get_verdict()
            verdict['judgement_id'] = judgement['id']

            g.judgements.append(judgement)
            g.verdicts.append(verdict)

    return jsonify_data()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():

    observables = filter_observables(get_observables())
    data = []

    if not observables:
        return jsonify_data(data)

    for observable in observables:
        type_ = current_app.config['AUTOFOCUS_OBSERVABLE_TYPES'][
            observable['type']
        ]
        data.append(
            {
                'id': 'ref-palo-alto-autofocus-search-{type}-{value}'.format(
                    **observable
                ),
                'title': f'Search for this {type_}',
                'description': f'Look up this {type_} on {SOURCE_NAME}',
                'url': Entity.get_source_uri(
                    observable['type'], observable['value']
                ),
                'categories': ['Search', SOURCE_NAME]
            }
        )

    return jsonify_data(data)
