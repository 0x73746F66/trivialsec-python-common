from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.member_mfa'

class MemberMfa(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('member_mfa', 'member_id')
        self.member_id = kwargs.get('member_id')
        self.type = kwargs.get('type')
        self.name = kwargs.get('name')
        self.webauthn_id = kwargs.get('webauthn_id')
        self.webauthn_public_key = kwargs.get('webauthn_public_key')
        self.webauthn_metadata = kwargs.get('webauthn_metadata')
        self.created_at = kwargs.get('created_at')

class MemberMfas(DatabaseIterators):
    def __init__(self):
        super().__init__('MemberMfa')
