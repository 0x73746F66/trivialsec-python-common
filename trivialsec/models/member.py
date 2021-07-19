from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators
from trivialsec.helpers.database import mysql_adapter
from .role import Role


__module__ = 'trivialsec.models.member'
__table__ = 'members'
__pk__ = 'member_id'

try:
    from flask_login import UserMixin
except Exception:
    class UserMixin:
        def __str__(self):
            # placeholder
            pass
        def __getattr__(self, attr):
            # placeholder
            pass

class Member(UserMixin, DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.member_id = kwargs.get('member_id')
        self.email = kwargs.get('email')
        self.account_id = kwargs.get('account_id')
        self.verified = bool(kwargs.get('verified'))
        self.scratch_code = kwargs.get('scratch_code')
        self.registered = kwargs.get('registered')
        self.confirmation_url = kwargs.get('confirmation_url')
        self.confirmation_sent = bool(kwargs.get('confirmation_sent'))
        self.roles = []

    def __setattr__(self, name, value):
        if name in ['verified', 'confirmation_sent']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_id(self):
        return self.member_id

    def get_roles(self):
        sql = "SELECT role_id FROM members_roles WHERE member_id = %(member_id)s"
        with mysql_adapter as database:
            results = database.query(sql, {'member_id': self.member_id})
            for val in results:
                if not any(isinstance(x, Role) and x.role_id == val['role_id'] for x in self.roles):
                    role = Role(role_id=val['role_id'])
                    if role.hydrate():
                        self.roles.append(role)

        return self

    def add_role(self, role: Role)->bool:
        insert_stmt = "INSERT INTO members_roles (member_id, role_id) VALUES (%(member_id)s, %(role_id)s) ON DUPLICATE KEY UPDATE member_id=member_id;"
        with mysql_adapter as database:
            new_id = database.query(insert_stmt, {'member_id': self.member_id, 'role_id': role.role_id})
            if new_id:
                self.roles.append(role)
                return True

        return False

    def remove_role(self, role: Role)->bool:
        delete_stmt = "DELETE FROM members_roles WHERE member_id=%(member_id)s AND role_id=%(role_id)s;"
        with mysql_adapter as database:
            new_id = database.query(delete_stmt, {'member_id': self.member_id, 'role_id': role.role_id})
            if new_id:
                self.roles.append(role)
                return True

        return False

class Members(DatabaseIterators):
    def __init__(self):
        super().__init__('Member', __table__, __pk__)
