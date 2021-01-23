from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.apikey'

class ApiKey(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('api_keys', 'api_key')
        self.api_key = kwargs.get('api_key')
        self.api_key_secret = kwargs.get('api_key_secret')
        self.comment = kwargs.get('comment')
        self.member_id = kwargs.get('member_id')
        self.allowed_origin = kwargs.get('allowed_origin')
        self.active = bool(kwargs.get('active'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['active']:
            value = bool(value)
        super().__setattr__(name, value)

class ApiKeys(DatabaseIterators):
    def __init__(self):
        super().__init__('ApiKey')
