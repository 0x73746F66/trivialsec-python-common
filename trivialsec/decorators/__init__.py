import json
from time import time, sleep
from functools import wraps
from urllib.parse import urlencode
from urllib import request as urlrequest
from flask_login import login_user, current_user
from flask import abort, request, url_for, redirect, jsonify
from trivialsec.helpers.hmac import validate
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.models.apikey import ApiKey
from trivialsec.models.member import Member
from trivialsec.services.roles import is_internal_member, is_support_member, is_billing_member, is_audit_member, is_owner_member


__module__ = 'trivialsec.decorators'

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
            body = request.get_json()
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
                    if 'timeout-or-duplicate' in siteverify['error-codes']:
                        return jsonify({
                            'status': 'retry'
                        })
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
                api_key = validate(
                    raw=request.get_data(as_text=True),
                    request_method=request.method,
                    uri=request.path,
                    headers=request.headers,
                    not_before_seconds=not_before_seconds,
                    expire_after_seconds=expire_after_seconds
                )
                if not isinstance(api_key, ApiKey):
                    return abort(401)
                # Success - application login and process the request
                member = Member(member_id=api_key.member_id)
                member.hydrate(ttl_seconds=30)
                login_user(member)
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.exception(err)
                ret = abort(401)
            return ret

        return f_require_hmac
    return deco_require_hmac

def internal_users(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_internal_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_support(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_support_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_billing(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_billing_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_audit(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_audit_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_owner(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_owner_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view
