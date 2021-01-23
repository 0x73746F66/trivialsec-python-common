from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.invitation'

class Invitation(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('invitations', 'invitation_id')
        self.invitation_id = kwargs.get('invitation_id')
        self.account_id = kwargs.get('account_id')
        self.invited_by_member_id = kwargs.get('invited_by_member_id')
        self.member_id = kwargs.get('member_id')
        self.role_id = kwargs.get('role_id')
        self.email = kwargs.get('email')
        self.confirmation_url = kwargs.get('confirmation_url')
        self.confirmation_sent = bool(kwargs.get('confirmation_sent'))
        self.message = kwargs.get('message')
        self.deleted = bool(kwargs.get('deleted'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['confirmation_sent', 'deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Invitations(DatabaseIterators):
    def __init__(self):
        super().__init__('Invitation')
