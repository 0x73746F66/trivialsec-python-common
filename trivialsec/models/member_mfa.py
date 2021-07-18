from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.member_mfa'

class MemberMfa(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('member_mfa', 'mfa_id')
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

class MemberMfas(DatabaseIterators):
    def __init__(self):
        super().__init__('MemberMfa')
