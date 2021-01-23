from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.link'

class Link(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('links', 'link_id')
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

class Links(DatabaseIterators):
    def __init__(self):
        super().__init__('Link')
