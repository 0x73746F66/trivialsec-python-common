from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
import hashlib
import hmac
from trivialsec.models.apikey import ApiKey
from .log_manager import logger


__module__ = 'trivialsec.helpers'

supported_digests = {
    'HMAC-SHA256': hashlib.sha256,
    'HMAC-SHA512': hashlib.sha512,
    'HMAC-SHA3-256': hashlib.sha3_256,
    'HMAC-SHA3-384': hashlib.sha3_384,
    'HMAC-SHA3-512': hashlib.sha3_512,
    'HMAC-BLAKE2B512': hashlib.blake2b,
}

def extract_auth_headers(headers: dict) -> dict:
    return {
        'date': headers.get('X-Date'),
        'digest': headers.get('X-Digest'),
        'apikey': headers.get('X-ApiKey'),
        'signature': headers.get('X-Signature'),
    }

def validate(raw: str, request_method: str, uri: str, headers: dict, not_before_seconds: int = 3, expire_after_seconds: int = 3) -> ApiKey:
    incoming_headers = extract_auth_headers(headers)
    if incoming_headers.get('digest') not in supported_digests.keys():
        logger.debug(f'X-Digest [{incoming_headers.get("digest")}] not supported')
        return None
    # base64 encode json for signing
    b64 = ''
    if raw:
        b64 = urlsafe_b64encode(raw.strip().encode('ascii')).decode('ascii')
    # not_before prevents replay attacks
    incoming_date = incoming_headers.get('date')
    compare_date = datetime.fromisoformat(incoming_date if not incoming_date.endswith('+00:00') else incoming_date[:-6])
    not_before = datetime.utcnow() - timedelta(seconds=not_before_seconds)
    expire_after = datetime.utcnow() + timedelta(seconds=expire_after_seconds)
    # expire_after can assist with support for offline/aeroplane mode
    if compare_date < not_before or compare_date > expire_after:
        logger.debug(f'compare_date {compare_date} not_before {not_before} expire_after {expire_after}')
        return None
    # fetch the correct shared-secret from database using ApiKey
    api_key = ApiKey(api_key=incoming_headers.get("apikey"))
    api_key.hydrate(ttl_seconds=3)
    if api_key.api_key_secret is None:
        logger.info(f'Missing api_key: {incoming_headers.get("apikey")}')
        return None
    if api_key.active is not True:
        logger.info(f'Disabled api_key: {incoming_headers.get("apikey")}')
        return None
    # Signing structure
    signing_data = bytes(f'{request_method}\n{uri}\n{incoming_date}\n{b64}'.strip("\n"), 'utf-8')
    # Sign HMAC using server-side secret
    compare_hmac = hmac.new(bytes(api_key.api_key_secret, 'utf-8'), signing_data, supported_digests.get(incoming_headers.get("digest"))).hexdigest()
    # Compare server-side HMAC with client provided HMAC
    if not hmac.compare_digest(compare_hmac, incoming_headers.get("signature")):
        logger.debug(f'api_key {api_key.api_key} {api_key.comment} signing_data {signing_data} incoming_hmac {incoming_headers.get("signature")} compare_hmac {compare_hmac}')
        return None

    return api_key
