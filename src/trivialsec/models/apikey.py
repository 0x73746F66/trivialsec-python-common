from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.apikey'
__table__ = 'api_keys'
__pk__ = 'api_key'

class ApiKey(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.api_key = kwargs.get('api_key')
        self.api_key_secret = kwargs.get('api_key_secret')
        self.comment = kwargs.get('comment')
        self.member_id = kwargs.get('member_id')
        self.active = bool(kwargs.get('active'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['active']:
            value = bool(value)
        super().__setattr__(name, value)

class ApiKeys(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('ApiKey', __table__, __pk__)
