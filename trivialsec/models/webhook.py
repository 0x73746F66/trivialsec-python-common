from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.webhook'

class Webhook(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('webhooks', 'webhook_id')
        self.webhook_id = kwargs.get('webhook_id')
        self.account_id = kwargs.get('account_id')
        self.webhook_secret = kwargs.get('webhook_secret')
        self.target = kwargs.get('target')
        self.comment = kwargs.get('comment')
        self.active = bool(kwargs.get('active'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['active']:
            value = bool(value)
        super().__setattr__(name, value)

class Webhooks(DatabaseIterators):
    def __init__(self):
        super().__init__('Webhook')
