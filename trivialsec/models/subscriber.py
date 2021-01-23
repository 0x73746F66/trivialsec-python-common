from trivialsec.models import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.subscriber'

class Subscriber(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('subscribers', 'subscriber_id')
        self.subscriber_id = kwargs.get('subscriber_id')
        self.email = kwargs.get('email')
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Subscribers(DatabaseIterators):
    def __init__(self):
        super().__init__('Subscriber')
