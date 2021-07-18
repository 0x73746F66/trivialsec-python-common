from os import getenv
from datetime import datetime
import re
import socket
import ipaddress
import boto3
import botocore
from hashlib import sha224
from random import randint
from base64 import b32encode
from dateutil.tz import tzlocal
from passlib.hash import pbkdf2_sha256
from gunicorn.glogging import logging
from mohawk import Receiver
from trivialsec.helpers.config import config
from trivialsec.models.apikey import ApiKey
from trivialsec.services.apikey import get_valid_key


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers'

def check_domain_rules(domain_name: str):
    # TODO implement
    return True

def check_subdomain_rules(sub_domain: str, domain_name: str = None) -> bool:
    if domain_name is not None:
        return sub_domain.endswith(domain_name) and domain_name != sub_domain

    parts = sub_domain.split('.')
    if len(parts) > 2:
        return True

    return False

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

def cidr_address_list(cidr: str)->list:
    ret = []
    if '/' not in cidr:
        ret.append(cidr)
        return ret
    for ip_addr in ipaddress.IPv4Network(cidr, strict=False):
        if ip_addr.is_global:
            ret.append(str(ip_addr))

    return ret

def oneway_hash(input_string: str)->str:
    return sha224(bytes(input_string, 'ascii')).hexdigest()

def hash_passphrase(passphrase, rounds: int = 8000, salt_size: int = 10):
    return pbkdf2_sha256.using(rounds=rounds, salt_size=salt_size).hash(passphrase) # pylint: disable=no-member

def check_encrypted_passphrase(passphrase, hashed):
    return pbkdf2_sha256.verify(passphrase, hashed)

def get_boto3_client(service: str, region_name: str, aws_profile: str = None, role_arn: str = None):
    boto_params = {
        'service_name': service,
        'region_name': region_name
    }
    session_params = {'region_name': region_name}
    if aws_profile:
        session_params['profile_name'] = aws_profile
    else:
        session_params['aws_access_key_id'] = getenv('AWS_ACCESS_KEY_ID', default=getenv('TF_VAR_aws_access_key_id'))
        session_params['aws_secret_access_key'] = getenv('AWS_SECRET_ACCESS_KEY', default=getenv('TF_VAR_aws_secret_access_key'))

    base_session = boto3.session.Session(**session_params)

    if role_arn:
        base_session = assumed_role_session(role_arn, base_session)
    else:
        boto_params['aws_access_key_id'] = getenv('AWS_ACCESS_KEY_ID')
        boto_params['aws_secret_access_key'] = getenv('AWS_SECRET_ACCESS_KEY')

    return base_session.client(**boto_params)

def assumed_role_session(role_arn: str, base_session: botocore.session.Session, session_name: str = None, external_id: str = None):
    if isinstance(base_session, boto3.session.Session):
        base_session = base_session._session # pylint: disable=protected-access

    fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
        client_creator=base_session.create_client,
        source_credentials=base_session.get_credentials(),
        role_arn=role_arn,
        extra_args={
            'RoleSessionName': session_name,
            'ExternalId': external_id
        }
    )
    credentials = botocore.credentials.DeferredRefreshableCredentials(
        method='assume-role',
        refresh_using=fetcher.fetch_credentials,
        time_fetcher=lambda: datetime.now(tzlocal())
    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = credentials # pylint: disable=protected-access

    return boto3.Session(botocore_session=botocore_session)

def default(func, ex: Exception, value):
    try:
        return func()
    except ex:
        return value

def is_valid_email(address) -> bool:
    try:
        matched = re.match(r'^[a-z\d]([\w\-]*[a-z\d]|[\w\+\-\.]*[a-z\d]{2,}|[a-z\d])*@[a-z\d]([\w\-]*[a-z\d]|[\w\-\.]*[a-z\d]{2,}|[a-z\d]){4,}?.[a-z]{2,}$', address)
        return bool(matched)
    except Exception: # not a valid address
        return False

def check_email_rules(email_addr: str) -> bool:
    parts = email_addr.split('@')
    if len(parts) != 2:
        logger.info('check_email_rules: invalid format')
        return False

    res = check_domain_rules(parts[1])
    if not res:
        logger.info('check_email_rules: invalid domain')
        return False

    if not is_valid_email(email_addr):
        logger.info('check_email_rules: validation error')
        return False

    return True

def extract_server_version(str_value: str) -> tuple:
    trim_values = [
        'via:',
        'x-cache: miss',
        'x-cache: miss from',
    ]
    clean_names = [
        'cloudfront',
        'varnish',
        'wp engine',
        'microsoft-httpapi',
        'amazons3'
    ]
    ignore_list = [
        'no "server" line in header',
        'server-processing-duration-in-ticks:',
        'iterable-links',
        'x-cacheable: non',
        'x-cacheable: short',
        'nib.com.au',
    ]
    server_name = str_value.lower()
    for ignore_str in ignore_list:
        if ignore_str in server_name:
            return None, None

    for drop_str in trim_values:
        server_name = server_name.replace(drop_str, '').strip()

    server_version = None
    if '/' in server_name and len(server_name.split('/')) == 2:
        server_name, server_version = server_name.split('/')
        matches = re.search(r'\d+(=?\.(\d+(=?\.(\d+)*)*)*)*', server_version)
        if matches:
            server_version = matches.group()

    if server_version is None:
        matches = re.search(r'\d+(=?\.(\d+(=?\.(\d+)*)*)*)*', server_name)
        if matches:
            server_version = matches.group()

    if server_version is not None and server_version in server_name:
        server_name = server_name.replace(server_version, '')

    for name in clean_names:
        if name in str_value.lower():
            server_name = name

    if server_name == '':
        server_name = None
    if server_version is not None:
        server_version = server_version.strip()
    if server_name is not None:
        server_name = server_name.strip()

    return server_name, server_version

def mohawk_receiver(request, algorithm :str = 'sha256'):
    authorization_header = request.headers.get('Authorization')
    if not authorization_header:
        logger.error('no Authorization header')
        return None

    def seen_nonce(sender_id, nonce, timestamp):
        key = '{id}:{nonce}:{ts}'.format(id=sender_id, nonce=nonce, ts=timestamp)
        if config._redis.get(key): # pylint: disable=protected-access
            # We have already processed this nonce + timestamp.
            return True
        else:
            # Save this nonce + timestamp for later.
            config._redis.set(key, '1') # pylint: disable=protected-access
            return False
    def lookup_credentials(sender_id):
        apikey :ApiKey = get_valid_key(sender_id)
        if apikey is None or not isinstance(apikey, ApiKey):
            logger.error('no apikey')
            return None
        if apikey.allowed_origin and request.referrer != apikey.allowed_origin:
            logger.error(f'referrer {request.referrer} not an allowed origin')
            return None
        credentials = {'id': sender_id, 'key': apikey.api_key_secret, 'algorithm': algorithm}
        return credentials
    content_type = request.headers.get('Content-Type')
    content = request.get_data(as_text=True)
    logger.debug(f'mohawk_receiver url {request.base_url} method {request.method} content {content} content_type {content_type} algorithm {algorithm}')
    try:
        return Receiver(
            credentials_map=lookup_credentials,
            request_header=authorization_header,
            url=request.base_url,
            method=request.method,
            content=content,
            content_type=content_type,
            seen_nonce=seen_nonce,
            timestamp_skew_in_seconds=3)
    except Exception as ex:
        logger.exception(ex)
        return ex
