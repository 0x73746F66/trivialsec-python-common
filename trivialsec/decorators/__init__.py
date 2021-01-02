import hashlib
import hmac
import json
from base64 import b64encode
from time import time, sleep
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlencode
from urllib import request as urlrequest
from flask_login import login_user
from flask import request, abort
from trivialsec.helpers import request_body
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.models import ApiKey, Plan, Member, Account


def control_timing_attacks(seconds: float):
    def deco_control_timing_attacks(func):
        @wraps(func)
        def f_control_timing_attacks(*args, **kwargs):
            start = time()
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.exception(err)
                ret = err
            end = time()
            elapsed_time = end - start
            logger.debug(f'elapsed_time {elapsed_time}')
            if elapsed_time < seconds:
                remaining = seconds - elapsed_time - 0.03
                sleep(remaining)
            return ret

        return f_control_timing_attacks
    return deco_control_timing_attacks

def require_recaptcha(action: str):
    def deco_require_recaptcha(func):
        @wraps(func)
        def f_require_recaptcha(*args, **kwargs):
            body = request_body()
            if 'recaptcha_token' not in body:
                logger.warning('missing recaptcha_token')
                return abort(403)

            params = urlencode({
                'secret': config.recaptcha_secret_key,
                'response': body['recaptcha_token']
            }).encode('ascii')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            req = urlrequest.Request(url)
            if config.http_proxy is not None:
                req.set_proxy(config.http_proxy, 'http')
            if config.https_proxy is not None:
                req.set_proxy(config.https_proxy, 'https')
            with urlrequest.urlopen(req, data=params) as resp:
                siteverify = json.loads(resp.read().decode('utf8'))
                logger.info(siteverify)
                logger.info(f'resp.code {resp.code}')
                if resp.code != 200:
                    logger.warning(f'{action} recaptcha code {resp.code}')
                    return abort(403)
                if siteverify['success']:
                    if siteverify['score'] < 0.6:
                        logger.warning(f'recaptcha score {siteverify["score"]}')
                        return abort(403)
                    if action and siteverify['action'] != action:
                        logger.warning(f'{action} recaptcha code {resp.code}')
                        return abort(403)
                elif len(siteverify['error-codes']) > 0:
                    logger.error(f"recaptcha {'|'.join(siteverify['error-codes'])}")
                    return abort(403)
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.exception(err)
                ret = err

            return ret

        return f_require_recaptcha
    return deco_require_recaptcha

def require_hmac(not_before_seconds: int = 3, expire_after_seconds: int = 3):
    def deco_require_hmac(func):
        @wraps(func)
        def f_require_hmac(*args, **kwargs):
            try:
                # logger.info(f'referrer {request.referrer}')
                incoming_data = request.get_data(as_text=True)
                incoming_date = request.headers.get('X-Date')
                incoming_digest = request.headers.get('X-Digest')
                incoming_apikey = request.headers.get('X-ApiKey')
                incoming_hmac = request.headers.get('X-Signature')
                supported_digests = {
                    'HMAC-SHA256': hashlib.sha256,
                    'HMAC-SHA512': hashlib.sha512,
                    'HMAC-SHA3-256': hashlib.sha3_256,
                    'HMAC-SHA3-384': hashlib.sha3_384,
                    'HMAC-SHA3-512': hashlib.sha3_512,
                    'HMAC-BLAKE2B512': hashlib.blake2b,
                }
                if incoming_digest not in supported_digests.keys():
                    logger.debug(f'X-Digest [{incoming_digest}] not supported')
                    return abort(401)
                # base64 encode json for signing
                if incoming_data:
                    incoming_data = b64encode(incoming_data.encode('ascii')).decode('ascii')
                # not_before prevents replay attacks
                compare_date = datetime.fromisoformat(incoming_date if not incoming_date.endswith('+00:00') else incoming_date[:-6])
                not_before = datetime.utcnow() - timedelta(seconds=not_before_seconds)
                expire_after = datetime.utcnow() + timedelta(seconds=expire_after_seconds)
                # expire_after can assist with support for offline/aeroplane mode
                if compare_date < not_before or compare_date > expire_after:
                    logger.debug(f'compare_date {compare_date} not_before {not_before} expire_after {expire_after}')
                    return abort(401)
                # fetch the correct shared-secret from database using ApiKey
                api_key = ApiKey(api_key=incoming_apikey)
                api_key.hydrate()
                if api_key.api_key_secret is None:
                    logger.info(f'Missing api_key: {incoming_apikey}')
                    return abort(401)
                # Signing structure
                signing_data = bytes(f'{request.method}\n{request.path}\n{incoming_date}\n{incoming_data}'.strip("\n"), 'utf-8')
                # Sign HMAC using server-side secret
                compare_hmac = hmac.new(bytes(api_key.api_key_secret, 'utf-8'), signing_data, supported_digests.get(incoming_digest)).hexdigest()
                # Compare server-side HMAC with client provided HMAC
                if not hmac.compare_digest(compare_hmac, incoming_hmac):
                    logger.debug(f'api_key {api_key.api_key} {api_key.comment} signing_data {signing_data} incoming_hmac {incoming_hmac} compare_hmac {compare_hmac}')
                    return abort(401)
                # Success - application login and process the request
                member = Member(member_id=api_key.member_id)
                member.hydrate()
                login_user(member)
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.exception(err)
                ret = abort(401)
            return ret

        return f_require_hmac
    return deco_require_hmac
