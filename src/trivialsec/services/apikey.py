from gunicorn.glogging import logging
from trivialsec.models.apikey import ApiKey


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.services.apikey'

def get_valid_key(key :str) -> ApiKey:
    api_key = ApiKey(api_key=key)
    api_key.hydrate(ttl_seconds=3)
    if api_key.api_key_secret is None:
        logger.info(f'Missing api_key: {key}')
        return None
    if api_key.active is not True:
        logger.info(f'Disabled api_key: {key}')
        return None

    return api_key

def get_public_api_key(member_id :int) -> ApiKey:
    api_key = ApiKey(member_id=member_id, comment='public-api')
    api_key.hydrate(['member_id', 'comment'], ttl_seconds=3)
    if api_key.api_key_secret is None:
        logger.info(f'Missing public-api key for member_id: {member_id}')
        return None
    if api_key.active is not True:
        logger.info(f'Disabled public-api key for member_id: {member_id}')
        return None

    return api_key
