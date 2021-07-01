from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from gunicorn.glogging import logging

logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers'

supported_digests = {
    'HMAC-SHA256': hashlib.sha256,
    'HMAC-SHA512': hashlib.sha512,
    'HMAC-SHA3-256': hashlib.sha3_256,
    'HMAC-SHA3-384': hashlib.sha3_384,
    'HMAC-SHA3-512': hashlib.sha3_512,
    'HMAC-BLAKE2B512': hashlib.blake2b,
}

def parse_auth_header(header :str) -> dict:
    return dict(re.compile('(\w+)[:=] ?"?(\w+)"?').findall(header))

def validate(api_key_secret :str, raw: str, request_method: str, uri: str, hawk_values: dict, not_before_seconds: int = 3, expire_after_seconds: int = 3, port :int = 443) -> bool:
    incoming_key = hawk_values.get('id')
    incoming_ts = hawk_values.get('ts')
    incoming_digests = hawk_values.get('algo')
    incoming_signature = hawk_values.get('mac')

    if incoming_digests not in supported_digests.keys():
        logger.debug(f'algo {incoming_digests} not supported')
        return False

    # base64 encode json for signing
    b64 = ''
    if raw:
        b64 = urlsafe_b64encode(raw.strip().encode('ascii')).decode('ascii')
    # not_before prevents replay attacks
    compare_date = datetime.fromtimestamp(incoming_ts)
    not_before = datetime.utcnow() - timedelta(seconds=not_before_seconds)
    expire_after = datetime.utcnow() + timedelta(seconds=expire_after_seconds)
    # expire_after can assist with support for offline/aeroplane mode
    if compare_date < not_before or compare_date > expire_after:
        logger.debug(f'compare_date {compare_date} not_before {not_before} expire_after {expire_after}')
        return False
    # Signing structure
    signing_data = bytes(f'{incoming_ts}\n{request_method}\n{uri}\n{str(port)}\n{b64}'.strip("\n"), 'utf-8')
    # Sign HMAC using server-side secret
    request_mac = hmac.new(bytes(api_key_secret, 'utf-8'), signing_data, supported_digests.get(incoming_digests)).hexdigest()
    # Compare server-side HMAC with client provided HMAC
    if not hmac.compare_digest(request_mac, incoming_signature):
        logger.debug(f'api_key {incoming_key} ext {hawk_values.get("ext")} signing_data {signing_data} incoming_hmac {incoming_signature} compare_hmac {request_mac}')
        return False

    return True
