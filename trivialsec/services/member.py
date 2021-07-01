from gunicorn.glogging import logging
from trivialsec.helpers import check_email_rules, check_encrypted_password
from trivialsec.models.member import Member


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.services.member'
