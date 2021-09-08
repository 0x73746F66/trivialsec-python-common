from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.link'
__table__ = 'links'
__pk__ = 'link_id'

class Link(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.link_id = kwargs.get('link_id')
        self.campaign = kwargs.get('campaign')
        self.channel = kwargs.get('channel')
        self.slug = kwargs.get('slug')
        self.deleted = bool(kwargs.get('deleted'))
        self.expires = kwargs.get('expires')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Links(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Link', __table__, __pk__)
