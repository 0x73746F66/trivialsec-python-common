import re
import socket
import hashlib
import validators
from passlib.hash import pbkdf2_sha256
from gunicorn.glogging import logging


__module__ = 'trivialsec.helpers'
logger = logging.getLogger(__name__)

def check_subdomain_rules(sub_domain :str, domain_name :str = None) -> bool:
    if domain_name is not None:
        return sub_domain.endswith(domain_name) and domain_name != sub_domain

    parts = sub_domain.split('.')
    return len(parts) > 2

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

def oneway_hash(input_string :str)->str:
    return hashlib.sha224(bytes(input_string, 'ascii')).hexdigest()

def hash_passphrase(passphrase, rounds: int = 8000, salt_size: int = 10):
    return pbkdf2_sha256.using(rounds=rounds, salt_size=salt_size).hash(passphrase) # pylint: disable=no-member

def check_encrypted_passphrase(passphrase, hashed):
    return pbkdf2_sha256.verify(passphrase, hashed)

def default(func, ex: Exception, value):
    try:
        return func()
    except ex:
        return value

def check_email_rules(email_addr :str) -> bool:
    parts = email_addr.split('@')
    if len(parts) != 2:
        logger.info('check_email_rules: invalid format')
        return False

    res = validators.domain(parts[1]) is True
    if not res:
        logger.info('check_email_rules: invalid domain')
        return False

    if not validators.email(email_addr):
        logger.info('check_email_rules: validation error')
        return False

    return True
