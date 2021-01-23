import string
import secrets
import uuid
from trivialsec.helpers.config import config
from trivialsec.helpers import check_email_rules, hash_password, oneway_hash
from trivialsec.models.account import Account, AccountConfig
from trivialsec.models.apikey import ApiKey
from trivialsec.models.member import Member
from trivialsec.models.plan import Plan
from trivialsec.models.role import Role


__module__ = 'trivialsec.services.accounts'

def generate_api_key_secret(sequence_range: int = 8):
    sequence = string.ascii_letters + string.digits
    return str(uuid.uuid5(uuid.NAMESPACE_URL, ''.join(secrets.choice(sequence) for _ in range(sequence_range)))).replace('-', '')

def generate_api_key():
    return generate_api_key_secret(32).upper()

def register(email_addr: str, passwd: str, selected_plan: dict, alias=None, verified=False, account_id=None, role_id=Role.ROLE_OWNER_ID) -> Member:
    res = check_email_rules(email_addr)
    if not res:
        return None

    member = Member(email=email_addr)
    if member.exists(['email']):
        return None

    account = Account(
        billing_email=email_addr,
        account_id=account_id,
        alias=alias or email_addr,
        verification_hash=oneway_hash(email_addr),
        socket_key=str(uuid.uuid5(uuid.NAMESPACE_URL, email_addr))
    )
    if account_id is not None:
        account.hydrate()
    elif account.exists(['verification_hash']):
        account.hydrate(by_column='verification_hash')
    else:
        account.persist()
        account_config = AccountConfig(account_id=account.account_id)
        account_config.persist()
        selected_plan['account_id'] = account.account_id
        plan = Plan(**selected_plan)
        plan.persist()

    member.account_id = account.account_id
    member.password = hash_password(passwd)
    member.confirmation_url = f"/confirmation/{account.verification_hash}" if not verified else 'verified'
    if verified:
        member.verified = True
    member.persist()
    member.add_role(Role(role_id=role_id))
    member.get_roles()

    ApiKey(
        api_key=generate_api_key(),
        api_key_secret=generate_api_key_secret(),
        member_id=member.member_id,
        comment='public-api',
        allowed_origin=config.get_app().get("host_domain"),
        active=True
    ).persist()

    return member
