from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.account'
__table__ = 'accounts'
__pk__ = 'account_id'

class Account(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.account_id = kwargs.get('account_id')
        self.alias = kwargs.get('alias')
        self.billing_email = kwargs.get('billing_email')
        self.is_setup = bool(kwargs.get('is_setup', 0))
        self.socket_key = kwargs.get('socket_key')
        self.verification_hash = kwargs.get('verification_hash')
        self.registered = kwargs.get('registered')

    def __setattr__(self, name, value):
        if name in ['is_setup']:
            value = bool(value)
        super().__setattr__(name, value)

class Accounts(DatabaseIterators):
    def __init__(self):
        super().__init__('Account', __table__, __pk__)
