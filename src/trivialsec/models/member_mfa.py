from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.member_mfa'
__table__ = 'member_mfa'
__pk__ = 'mfa_id'

class MemberMfa(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.mfa_id = kwargs.get('mfa_id')
        self.member_id = kwargs.get('member_id')
        self.type = kwargs.get('type')
        self.name = kwargs.get('name')
        self.active = bool(kwargs.get('active'))
        self.totp_code = kwargs.get('totp_code')
        self.webauthn_id = kwargs.get('webauthn_id')
        self.webauthn_public_key = kwargs.get('webauthn_public_key')
        self.webauthn_challenge = kwargs.get('webauthn_challenge')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['active']:
            value = bool(value)
        super().__setattr__(name, value)

class MemberMfas(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('MemberMfa', __table__, __pk__)
