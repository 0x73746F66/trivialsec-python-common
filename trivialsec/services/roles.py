from trivialsec.models import Role, Member


def is_internal_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.internal_only:
            return True

    return False

def is_support_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == Role.ROLE_SUPPORT_ID:
            return True

    return False

def is_billing_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id in [Role.ROLE_BILLING_ID, Role.ROLE_OWNER_ID]:
            return True

    return False

def is_audit_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id in [Role.ROLE_AUDIT_ID, Role.ROLE_OWNER_ID]:
            return True

    return False

def is_owner_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == Role.ROLE_OWNER_ID:
            return True

    return False

def is_readonly_member(current_user: Member) -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == Role.ROLE_RO_ID:
            return True

    return False
