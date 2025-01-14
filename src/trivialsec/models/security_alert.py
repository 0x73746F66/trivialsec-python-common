from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.security_alert'
__table__ = 'security_alerts'
__pk__ = 'security_alert_id'

class SecurityAlert(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.security_alert_id = kwargs.get('security_alert_id')
        self.account_id = kwargs.get('account_id')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.hook_url = kwargs.get('hook_url')
        self.delivered = bool(kwargs.get('delivered'))
        self.delivered_at = kwargs.get('delivered_at')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['delivered']:
            value = bool(value)
        super().__setattr__(name, value)

class SecurityAlerts(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('SecurityAlert', __table__, __pk__)
