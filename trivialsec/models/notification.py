from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.notification'
__table__ = 'notifications'
__pk__ = 'notification_id'

class Notification(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.notification_id = kwargs.get('notification_id')
        self.account_id = kwargs.get('account_id')
        self.description = kwargs.get('description')
        self.url = kwargs.get('url')
        self.marked_read = kwargs.get('marked_read')
        self.read_by = kwargs.get('read_by')
        self.created_at = kwargs.get('created_at')

class Notifications(DatabaseIterators):
    def __init__(self):
        super().__init__('Notification', __table__, __pk__)
