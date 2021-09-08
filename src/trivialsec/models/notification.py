from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.notification'
__table__ = 'notifications'
__pk__ = 'notification_id'

class Notification(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.notification_id = kwargs.get('notification_id')
        self.account_id = kwargs.get('account_id')
        self.description = kwargs.get('description')
        self.url = kwargs.get('url')
        self.marked_read = kwargs.get('marked_read')
        self.read_by = kwargs.get('read_by')
        self.created_at = kwargs.get('created_at')

class Notifications(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Notification', __table__, __pk__)
