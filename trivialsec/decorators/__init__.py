import json
import hashlib
import hmac
from time import time, sleep
from base64 import b64encode
from functools import wraps
from urllib.parse import urlencode
from urllib import request as urlrequest
from flask_login import current_user
from flask import Response, abort, request, url_for, redirect, jsonify, current_app as app
from gunicorn.glogging import logging
from trivialsec.helpers import messages
from trivialsec.helpers.config import config
from trivialsec.helpers.authz import verify_transaction
from trivialsec.models.member_mfa import MemberMfa
from trivialsec.services.roles import is_internal_member, is_support_member, is_billing_member, is_audit_member, is_owner_member


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.decorators'


def require_authz(func):
    @wraps(func)
    def deco_require_authz(*args, **kwargs):
        try:
            authorization_token = request.headers.get('X-Authorization-Token')
            if authorization_token is None:
                raise ValueError('X-Authorization-Token header is required')
            request_path = request.path[3:]
            authorized = False
            for u2f_key in current_user.u2f_keys:
                if verify_transaction(
                        secret_key=current_user.apikey.api_key_secret,
                        factor_key=u2f_key.get('webauthn_id'),
                        target=request_path,
                        authorization_token=authorization_token,
                    ):
                    authorized = True
                    break

            if hasattr(current_user, 'totp_mfa_id'):
                mfa = MemberMfa(mfa_id=current_user.totp_mfa_id)
                if mfa.hydrate() and verify_transaction(
                        secret_key=current_user.apikey.api_key_secret,
                        factor_key=mfa.totp_code,
                        target=request_path,
                        authorization_token=authorization_token,
                    ):
                    authorized = True

            if authorized is False:
                raise ValueError('authorized is False')
            return func(*args, **kwargs)
        except Exception as err:
            logger.exception(err)
            return Response('{"status": 401, "message": "Unauthorized"}', 401, {'Content-Type': 'application/json'})

    return deco_require_authz

def control_timing_attacks(seconds: float):
    def deco_control_timing_attacks(func):
        @wraps(func)
        def f_control_timing_attacks(*args, **kwargs):
            start = time()
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.error(err)
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

def require_recaptcha(action :str):
    def deco_require_recaptcha(func):
        @wraps(func)
        def f_require_recaptcha(*args, **kwargs):
            if app.debug:
                return func(*args, **kwargs)
            body = request.get_json(force=True, silent=True)
            if body is None:
                body = {}
            recaptcha_token = body.get('recaptcha_token')
            if recaptcha_token is None:
                logger.warning('missing recaptcha_token')
                return abort(403)

            params = urlencode({
                'secret': config.recaptcha_secret_key,
                'response': body.get('recaptcha_token')
            }).encode('ascii')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            req = urlrequest.Request(url)
            if config.http_proxy is not None:
                req.set_proxy(config.http_proxy, 'http')
            if config.https_proxy is not None:
                req.set_proxy(config.https_proxy, 'https')
            with urlrequest.urlopen(req, data=params) as resp:
                siteverify = json.loads(resp.read().decode('utf8'))
                logger.debug(siteverify)
                if resp.code != 200:
                    logger.warning(f'recaptcha siteverify response code {resp.code} {action}')
                    return abort(403)
                error_codes = siteverify.get('error-codes', [])
                score = siteverify.get('score', 1.0)
                if siteverify.get('success', False) and score < 0.6:
                    logger.warning(f'recaptcha score {score}')
                    return abort(403)
                siteverify_action = siteverify.get('action')
                if siteverify_action != action:
                    logger.warning(f'{siteverify_action} not match {action}')
                    return abort(403)
                if len(error_codes) > 0:
                    logger.error(f"recaptcha {'|'.join(error_codes)}")
                    if 'timeout-or-duplicate' in siteverify.get('error-codes', []):
                        return jsonify({
                            'status': 'retry',
                            'action': action
                        })
                    return abort(403)
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                logger.error(err)
                ret = err

            return ret

        return f_require_recaptcha
    return deco_require_recaptcha

def internal_users(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_internal_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('root.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_support(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_support_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('root.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_billing(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_billing_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('root.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_audit(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_audit_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('root.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_owner(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_owner_member(current_user)

        if not current_user.is_authenticated:
            return redirect(url_for('root.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def prepared_json(func):
    @wraps(func)
    def deco_prepared_json(*args, **kwargs):
        params = request.get_json(force=True, silent=True)
        if params is None:
            params = {}
        params['status'] = 'error'
        params['message'] = messages.ERR_ACCESS_DENIED
        if 'recaptcha_token' in params:
            del params['recaptcha_token']
        return func(params, *args, **kwargs)
    return deco_prepared_json
