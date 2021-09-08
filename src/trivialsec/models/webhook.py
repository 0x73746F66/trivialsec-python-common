from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.webhook'
__table__ = 'webhooks'
__pk__ = 'webhook_id'

class Webhook(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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

class Webhooks(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Webhook', __table__, __pk__)
