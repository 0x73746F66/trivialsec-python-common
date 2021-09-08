from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.key_value'
__table__ = 'key_values'
__pk__ = 'key_value_id'

class KeyValue(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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

class KeyValues(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('KeyValue', __table__, __pk__)
