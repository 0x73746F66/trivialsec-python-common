import hashlib
import hmac
from datetime import timedelta
from random import random
from base64 import b64encode
from .config import config
from . import oneway_hash

def get_transaction_id(secret_key :str, target :str) -> str:
    return b64encode(hmac.new(bytes(secret_key, "ascii"), bytes(target, "ascii"), hashlib.sha1).digest()).decode()

def start_transaction(key :str, target :str) -> str:
    transaction_id = get_transaction_id(key, target)
    config._redis.set(f'{config.app_version}{transaction_id}', oneway_hash(str(random())), ex=timedelta(seconds=config.session_expiry_minutes*60))
    return transaction_id

def get_authorization_token(factor_key :str, transaction_id :str) -> str:
    stored_nonce = config._redis.get(transaction_id)
    if stored_nonce is None:
        raise ValueError('authorization_token must have a valid transaction_id')
    return b64encode(hmac.new(bytes(factor_key, "ascii"), bytes(stored_nonce, "ascii"), hashlib.sha1).digest()).decode()

def verify_transaction(secret_key :str, factor_key : str, target :str, authorization_token :str) -> bool:
    transaction_id = get_transaction_id(secret_key, target)
    stored_authorization_token = get_authorization_token(factor_key, transaction_id)
    return authorization_token == stored_authorization_token
