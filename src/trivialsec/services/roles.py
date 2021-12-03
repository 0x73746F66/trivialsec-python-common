from trivialsec.models.role import Role
from trivialsec.models.member import Member


__module__ = 'trivialsec.services.roles'

def is_internal_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(role.internal_only for role in current_user.roles)

def is_support_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(role.role_id == Role.ROLE_SUPPORT_ID for role in current_user.roles)

def is_billing_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(
        role.role_id in [Role.ROLE_BILLING_ID, Role.ROLE_OWNER_ID]
        for role in current_user.roles
    )

def is_audit_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(
        role.role_id in [Role.ROLE_AUDIT_ID, Role.ROLE_OWNER_ID]
        for role in current_user.roles
    )

def is_owner_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(role.role_id == Role.ROLE_OWNER_ID for role in current_user.roles)

def is_readonly_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    return any(role.role_id == Role.ROLE_RO_ID for role in current_user.roles)
