from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.activity_log'
__table__ = 'activity_logs'
__pk__ = 'activity_log_id'

class ActivityLog(DatabaseHelpers):
    ACTION_USER_LOGIN = 'user_login'
    ACTION_USER_KEY_ROTATE = 'user_key_rotation'
    ACTION_USER_LOGOUT = 'user_logout'
    ACTION_DOMAIN_VERIFICATION_CHECK = 'domain_verification_check'
    ACTION_DOMAIN_METADATA_CHECK = 'domain_metadata_check'
    ACTION_CREATE_PROJECT = 'create_project'
    ACTION_ADDED_IPADDRESS = 'added_ipaddress'
    ACTION_ADDED_DOMAIN = 'added_domain'
    ACTION_ENABLE_DOMAIN = 'enabled_domain_automation'
    ACTION_DISABLE_DOMAIN = 'disabled_domain_automation'
    ACTION_ENABLE_PROJECT = 'enabled_project_automation'
    ACTION_DISABLE_PROJECT = 'disabled_project_automation'
    ACTION_DELETE_DOMAIN = 'deleted_domain'
    ACTION_DELETE_PROJECT = 'deleted_project'
    ACTION_ON_DEMAND_PASSIVE_SCAN = 'on_demand_passive_scan'
    ACTION_ON_DEMAND_ACTIVE_SCAN = 'on_demand_active_scan'
    ACTION_AUTO_PASSIVE_SCAN = 'auto_passive_scan'
    ACTION_AUTO_ACTIVE_SCAN = 'auto_active_scan'
    ACTION_USER_CHANGE_EMAIL_REQUEST = 'user_change_email_request'
    ACTION_USER_CREATED_INVITATION = 'user_created_invitation'
    ACTION_USER_RECOVERY_REQUEST = 'user_recovery_request'
    ACTION_APPROVED_RECOVERY_REQUEST = 'approved_recovery_request'
    ACTION_DENY_RECOVERY_REQUEST = 'deny_recovery_request'
    ACTION_USER_CHANGED_ACCOUNT = 'user_changed_account'
    ACTION_USER_CHANGED_MEMBER = 'user_changed_member'

    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.activity_log_id = kwargs.get('activity_log_id')
        self.member_id = kwargs.get('member_id')
        self.action = kwargs.get('action')
        self.description = kwargs.get('description')
        self.occurred = kwargs.get('occurred')

class ActivityLogs(DatabaseIterators):
    def __init__(self):
        super().__init__('ActivityLog', __table__, __pk__)
