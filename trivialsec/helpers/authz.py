import hashlib
import hmac
from datetime import timedelta
from random import random
from base64 import b64encode
from gunicorn.glogging import logging
from .config import config
from . import oneway_hash


__module__ = 'trivialsec.helpers.authz'
logger = logging.getLogger(__name__)

def get_transaction_id(secret_key :str, target :str) -> str:
    return b64encode(hmac.new(bytes(secret_key, "ascii"), bytes(target, "ascii"), hashlib.sha1).digest()).decode()

def start_transaction(target :str) -> str:
    secret_key = oneway_hash(str(random()))
    transaction_id = get_transaction_id(secret_key, target)
    cache_key = f'{config.app_version}{transaction_id}'
    config._redis.set(cache_key, secret_key, ex=timedelta(seconds=int(config.authz_expiry_seconds)))
    return transaction_id

def get_authorization_token(mfa_key :str, transaction_id :str) -> str:
    cache_key = f'{config.app_version}{transaction_id}'
    stored_value = config._redis.get(cache_key)
    if stored_value is None:
        raise ValueError('authorization_token must have a valid transaction_id')

    secret_key = stored_value.decode()
    authorization_token = oneway_hash(f'{cache_key}:{mfa_key}:{secret_key}')
    cache_key = f'{config.app_version}{authorization_token}'
    config._redis.set(cache_key, transaction_id, ex=timedelta(seconds=int(config.authz_expiry_seconds)))
    return authorization_token

def is_active_transaction(transaction_id :str, target :str) -> bool:
    cache_key_kid = f'{config.app_version}{transaction_id}'
    stored_value = config._redis.get(cache_key_kid)
    if stored_value is None:
        return False

    secret_key = stored_value.decode()
    gen_transaction_id = get_transaction_id(secret_key, target)
    if gen_transaction_id == transaction_id:
        return True

    return False

def verify_transaction(mfa_key : str, target :str, authorization_token :str) -> bool:
    cache_key_tid = f'{config.app_version}{authorization_token}'
    stored_value = config._redis.get(cache_key_tid)
    if stored_value is None:
        raise ValueError('authorization_token has no valid transaction_id available')

    transaction_id = stored_value.decode()
    cache_key_kid = f'{config.app_version}{transaction_id}'
    stored_value = config._redis.get(cache_key_kid)
    if stored_value is None:
        raise ValueError(f'transaction_id {transaction_id} has no valid secret_key available')

    secret_key = stored_value.decode()
    gen_transaction_id = get_transaction_id(secret_key, target)
    if gen_transaction_id != transaction_id:
        raise ValueError(f'transaction_id {transaction_id} is invalid for this request: {target}')

    stored_authorization_token = get_authorization_token(mfa_key, transaction_id)
    return authorization_token == stored_authorization_token
