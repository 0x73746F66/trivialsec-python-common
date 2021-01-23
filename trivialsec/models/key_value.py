from trivialsec.models import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.key_value'

class KeyValue(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('key_values', 'key_value_id')
        self.key_value_id = kwargs.get('key_value_id')
        self.type = kwargs.get('type')
        self.key = kwargs.get('key')
        self.value = kwargs.get('value')
        self.hidden = bool(kwargs.get('hidden'))
        self.active_date = kwargs.get('active_date')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['hidden']:
            value = bool(value)
        super().__setattr__(name, value)

class KeyValues(DatabaseIterators):
    def __init__(self):
        super().__init__('KeyValue')
