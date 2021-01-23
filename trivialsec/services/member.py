from trivialsec.helpers.log_manager import logger
from trivialsec.helpers import check_email_rules, check_encrypted_password
from trivialsec.models.member import Member


__module__ = 'trivialsec.services.member'

def handle_login(email_addr: str, password: str) -> Member:
    res = check_email_rules(email_addr)
    if not res:
        logger.info(f'check_email_rules {email_addr}')
        return None

    member = Member(email=email_addr)
    if not member.exists(['email']):
        logger.info(f'not exists {email_addr}')
        return None
    member.hydrate('email')

    if not check_encrypted_password(password, member.password):
        logger.info(f' given {password}')
        logger.info(f'stored {member.password}')
        return None

    return member
