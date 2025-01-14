from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter, replica_adapter
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

class Member(UserMixin, MySQL_Row_Adapter):
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
        stmt = "SELECT role_id FROM members_roles WHERE member_id = %(member_id)s"
        with replica_adapter as sql:
            results = sql.query(stmt, {'member_id': self.member_id})
            for val in results:
                if not any(isinstance(x, Role) and x.role_id == val['role_id'] for x in self.roles):
                    role = Role(role_id=val['role_id'])
                    if role.hydrate():
                        self.roles.append(role)

        return self

    def add_role(self, role: Role)->bool:
        insert_stmt = "INSERT INTO members_roles (member_id, role_id) VALUES (%(member_id)s, %(role_id)s) ON DUPLICATE KEY UPDATE member_id=member_id;"
        with replica_adapter as sql:
            new_id = sql.query(insert_stmt, {'member_id': self.member_id, 'role_id': role.role_id})
            if new_id:
                self.roles.append(role)
                return True

        return False

    def remove_role(self, role: Role)->bool:
        delete_stmt = "DELETE FROM members_roles WHERE member_id=%(member_id)s AND role_id=%(role_id)s;"
        with replica_adapter as sql:
            new_id = sql.query(delete_stmt, {'member_id': self.member_id, 'role_id': role.role_id})
            if new_id:
                self.roles.append(role)
                return True

        return False

class Members(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Member', __table__, __pk__)

    def find_by_role_id(self, role_id :int, account_id :int):
        stmt = 'SELECT r.member_id FROM members_roles r LEFT JOIN members m ON r.member_id = m.member_id WHERE r.role_id = %(role_id)s and m.account_id = %(account_id)s'
        items = []
        with replica_adapter as sql:
            results = sql.query(stmt, {'role_id': role_id, 'account_id': account_id})
            for val in results:
                if not any(isinstance(x, Member) and x.member_id == val['member_id'] for x in items):
                    member = Member(member_id=val['member_id'])
                    if member.hydrate():
                        items.append(member)
        self.set_items(items)
        return self
