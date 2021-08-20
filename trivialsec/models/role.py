from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.role'
__table__ = 'roles'
__pk__ = 'role_id'

class Role(MySQL_Row_Adapter):
    ROLE_SUPPORT = 'Support'
    ROLE_SUPPORT_ID = 5
    ROLE_AUDIT = 'Audit'
    ROLE_AUDIT_ID = 4
    ROLE_RO = 'Read Only'
    ROLE_RO_ID = 3
    ROLE_BILLING = 'Billing'
    ROLE_BILLING_ID = 2
    ROLE_OWNER = 'Owner'
    ROLE_OWNER_ID = 1

    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.role_id = kwargs.get('role_id')
        self.name = kwargs.get('name')
        self.internal_only = bool(kwargs.get('internal_only', 0))

    def __setattr__(self, name, value):
        if name in ['internal_only']:
            value = bool(value)
        super().__setattr__(name, value)

class Roles(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Role', __table__, __pk__)
