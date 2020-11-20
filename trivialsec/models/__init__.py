import importlib
import datetime
import json
import re
from os import isatty
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timedelta
from copy import copy
from random import shuffle, choice
from string import ascii_lowercase
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.database import mysql_adapter
from trivialsec.helpers import HTTPMetadata

__module__ = 'trivialsec.models'

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

class UpdateTable:
    def __init__(self, class_name: str, column: str, value, hydrate_using: list):
        module = importlib.import_module(__module__)
        class_ = getattr(module, class_name)
        self.__cls = class_()
        self.__cls.hydrate(hydrate_using)
        self.class_name = class_name
        self.column = column
        self.value = value
        setattr(self.__cls, column, value)

    def setattr(self, attr: str, value):
        setattr(self.__cls, attr, value)

    def persist(self):
        return self.__cls.persist()

    def __str__(self):
        return str(self.__cls)

    def __repr__(self):
        return str(self)

class DatabaseIterators:
    cache_key = None

    def __init__(self, class_name):
        self.__table = f"{re.sub(r'(?<!^)(?=[A-Z])', '_', class_name).lower()}s"
        self.__class_name = class_name
        self.__index = 0
        self.__items = []

    def _load_items(self, results: list):
        module = importlib.import_module(__module__)
        class_ = getattr(module, self.__class_name)
        for result in results:
            model = class_()
            for col, val in result.items():
                setattr(model, col, val)
            self.__items.append(model)
        self.__index = 0

    def find_by(self, search_filter: list, conditional: str = 'AND', order_by: list = None, limit: int = 1000, offset: int = 0, cache_key: str = False):
        if cache_key is not None:
            self.cache_key = cache_key
        module = importlib.import_module(__module__)
        class_ = getattr(module, self.__class_name)
        cls = class_()
        data = {}
        sql = f"SELECT * FROM {self.__table}"
        conditions = []
        for key, val in search_filter:
            if val is None:
                conditions.append(f' {key} is null ')
            elif isinstance(val, (list, tuple)):
                index = 0
                in_keys = []
                for _val in val:
                    _key = f'{key}{index}'
                    data[_key] = _val
                    index += 1
                    in_keys.append(f'%({_key})s')

                conditions.append(f' {key} in ({",".join(in_keys)}) ')
            else:
                data[key] = val
                conditions.append(f' {key} = %({key})s ')
        sql += f" WHERE {conditional.join(conditions)}"

        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            sql += f" ORDER BY {' '.join(order_by)}"
        if limit:
            sql += f' LIMIT {offset},{limit}'

        with mysql_adapter as database:
            results = database.query(sql, data, cache_key=self.cache_key)
            self._load_items(results)

        return self

    def load(self, order_by: list = None, limit: int = 1000, offset: int = 0, cache_key: str = None):
        if cache_key is not None:
            self.cache_key = cache_key
        module = importlib.import_module(__module__)
        class_ = getattr(module, self.__class_name)
        cls = class_()
        sql = f"SELECT * FROM {self.__table}"
        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            sql += f" ORDER BY {' '.join(order_by)}"
        if limit:
            sql += f' LIMIT {offset},{limit}'

        with mysql_adapter as database:
            results = database.query(sql, cache_key=self.cache_key)
            self._load_items(results)

        return self

    def distinct(self, column: str, limit: int = 1000) -> list:
        sql = f"SELECT DISTINCT({column}) FROM {self.__table}"
        if limit:
            sql += f' LIMIT {limit}'

        values = set()
        cache_key = f'{self.__table}/distinct_{column}'
        with mysql_adapter as database:
            results = database.query(sql, cache_key=cache_key)
            for result in results:
                for _, val in result.items():
                    values.add(val)

        return list(values)

    def count(self, query_filter: list = None, conditional: str = 'AND') -> int:
        data = {}
        sql = f"SELECT COUNT(*) as count FROM {self.__table}"
        if query_filter and isinstance(query_filter, list):
            conditions = []
            for key, val in query_filter:
                if val is None:
                    conditions.append(f' {key} is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditions.append(f' {key} in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditions.append(f' {key} = %({key})s ')
            sql += f" WHERE {conditional.join(conditions)}"

        with mysql_adapter as database:
            res = database.query_one(sql, data, cache_key=self.cache_key)
            return res.get('count', 0)
        return 0

    def pagination(self, search_filter: list = None, page_size: int = 10, page_num: int = 0, show_pages: int = 10, conditional: str = 'AND')->dict:
        data = {}
        sql = f"SELECT count(*) as records FROM {self.__table}"
        if search_filter and isinstance(search_filter, list):
            conditions = []
            for col in search_filter:
                key, val = col
                if val is None:
                    conditions.append(f' {key} is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditions.append(f' {key} in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditions.append(f' {key} = %({key})s ')
            sql += f' WHERE {conditional.join(conditions)} '

        result = None
        with mysql_adapter as database:
            result = database.query_one(sql, data)
            last_page = int(result['records'] / page_size) + 1
            first = min(max(1, page_num-1), max(1, last_page-show_pages))
            last = min(page_num+show_pages-1, last_page+1)
            result['prev'] = max(1, page_num-1)
            result['next'] = min(page_num+1, last_page)
            result['current_page'] = page_num
            result['last_page'] = last_page
            result['page_size'] = page_size
            pages = range(first, last)
            result['pages'] = list(pages)

        return result

    def set_items(self, items: list):
        self.__items = items
        self.__index = 0
        return self

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.__items)

    def __next__(self):
        try:
            result = self.__items[self.__index]
        except IndexError:
            self.__index = 0
            raise StopIteration
        self.__index += 1
        return result

    def __getitem__(self, item):
        return self.__items[item]

    def to_list(self):
        return self.__items

class DatabaseHelpers:
    __hash__ = object.__hash__
    cache_key = None

    def __init__(self, table, pk):
        self.__table = table
        self.__pk = pk
        self.__cols = set()

    def hydrate(self, by_column = None, value=None, conditional: str = 'AND')->bool:
        cache_key = f'{self.__table}/{self.__pk}/{self.__getattribute__(self.__pk)}'
        if by_column is None:
            by_column = self.__pk

        values = {}
        if isinstance(by_column, str):
            conditionals = f' {by_column} = %({by_column})s '
            values[by_column] = value if value is not None else self.__getattribute__(by_column)
            cache_key = f'{self.__table}/{by_column}/{values[by_column]}'
        elif isinstance(by_column, tuple):
            by_column, value = by_column
            conditionals = f' {by_column} = %({by_column})s '
            values[by_column] = value
            cache_key = f'{self.__table}/{by_column}/{values[by_column]}'
        elif isinstance(by_column, list):
            where = []
            for str_tuple in by_column:
                if isinstance(str_tuple, tuple):
                    by_column, value = str_tuple
                if isinstance(str_tuple, str):
                    by_column = str_tuple
                    values[by_column] = value if value is not None else self.__getattribute__(by_column)
                where.append(f"{by_column} = %({by_column})s")

            conditionals = f' {conditional} '.join(where)
            if self.__pk not in values:
                cache_parts = [f'table|{self.__table}']
                for col, dval in values.items():
                    cache_parts.append(f'{col}|{dval}')
                cache_parts.sort()
                cache_key = '/'.join(cache_parts)

        if self.cache_key is None:
            self.cache_key = cache_key

        result = None
        sql = f"SELECT * FROM {self.__table} WHERE {conditionals} LIMIT 1"
        with mysql_adapter as database:
            result = database.query_one(sql, values, cache_key=self.cache_key)
            if result:
                for col, val in result.items():
                    setattr(self, col, val)
                return True
        return False

    def exists(self, by_list: list = None, conditional: str = 'AND') -> bool:
        value = self.__getattribute__(self.__pk)
        with mysql_adapter as database:
            if not by_list:
                if not value:
                    logger.debug(f'Not exists {repr(self.__dict__)}')
                    return False
                pk_column = self.__pk
                sql = f"SELECT `{self.__pk}` FROM `{self.__table}` WHERE `{pk_column}` = %({pk_column})s LIMIT 1"
                value = value if value is not None else self.__getattribute__(pk_column)
                result = database.query_one(sql, {pk_column: value})
                if result is not None:
                    setattr(self, self.__pk, result[self.__pk])
                    return True
            if isinstance(by_list, list):
                where = []
                values = {}
                for str_tuple in by_list:
                    if isinstance(str_tuple, tuple):
                        pk_column, value = str_tuple
                    if isinstance(str_tuple, str):
                        pk_column = str_tuple
                        value = None
                    where.append(f"{pk_column} = %({pk_column})s")
                    value = value if value is not None else self.__getattribute__(pk_column)
                    values[pk_column] = value
                conditionals = f' {conditional} '.join(where)
                sql = f"SELECT {self.__pk} FROM {self.__table} WHERE {conditionals} LIMIT 1"
                result = database.query_one(sql, values)
                if result is not None:
                    setattr(self, self.__pk, result[self.__pk])
                    return True

        return False

    def persist(self, exists=None, invalidations: list = None) -> bool:
        data = {}
        values = []
        columns = []
        if invalidations is None:
            invalidations = []
        if exists is None:
            exists = True if self.__getattribute__(self.__pk) else self.exists()
        logger.debug(f'persist {"UPDATE" if exists else "INSERT"} {self.__table}')
        inv1 = f'{self.__table}/cols'
        if inv1 not in invalidations:
            invalidations.append(inv1)

        for prop in self.cols():
            _val = self.__getattribute__(prop)
            if not exists and _val is None:
                continue
            if isinstance(_val, bool):
                data[prop] = 1 if _val is True else 0
            elif isinstance(_val, datetime):
                data[prop] = _val.isoformat()
            elif _val is not None and isinstance(_val, object):
                data[prop] = str(_val)
            else:
                data[prop] = _val
            inv2 = f'{self.__table}/{prop}/{data[prop]}'
            if inv2 not in invalidations:
                invalidations.append(inv2)

        if self.__pk in data:
            inv3 = f'{self.__table}/{self.__pk}/{data[self.__pk]}'
            if inv3 not in invalidations:
                invalidations.append(inv3)

        with mysql_adapter as database:
            if exists is True:
                for col, _ in data.items():
                    if col != self.__pk:
                        values.append(f'{col} = %({col})s')
                update_stmt = f"UPDATE {self.__table} SET {', '.join(values)} WHERE {self.__pk} = %({self.__pk})s"
                changed = database.query(update_stmt, data, cache_key=None, invalidations=invalidations)
                if changed > 0:
                    return True
            if exists is False:
                for col, _ in data.items():
                    if _ is None:
                        continue
                    values.append(f'%({col})s')
                    columns.append(col)

                insert_stmt = f"INSERT INTO {self.__table} ({', '.join(columns)}) VALUES ({', '.join(values)})"
                logger.info(f'{insert_stmt} {repr(data)}')
                new_id = database.query(insert_stmt, data, cache_key=None, invalidations=invalidations)
                if new_id:
                    setattr(self, self.__pk, new_id)
                    self.hydrate()
                    return True

        return False

    def cols(self) -> list:
        if self.__cols:
            return self.__cols
        with mysql_adapter as database:
            self.__cols = database.table_cols(self.__table)
            return self.__cols
        return list()

class Account(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('accounts', 'account_id')
        self.account_id = kwargs.get('account_id')
        self.alias = kwargs.get('alias')
        self.plan_id = kwargs.get('plan_id', 1)
        self.billing_email = kwargs.get('billing_email')
        self.is_setup = bool(kwargs.get('is_setup', 0))
        self.socket_key = kwargs.get('socket_key')
        self.verification_hash = kwargs.get('verification_hash')
        self.registered = kwargs.get('registered')

    def __setattr__(self, name, value):
        if name in ['is_setup']:
            value = bool(value)
        super().__setattr__(name, value)

class Accounts(DatabaseIterators):
    def __init__(self):
        super().__init__('Account')

class AccountConfig(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('account_config', 'account_id')
        self.account_id = kwargs.get('account_id')
        self.default_role_id = kwargs.get('default_role_id')
        self.blacklisted_domains = kwargs.get('blacklisted_domains')
        self.blacklisted_ips = kwargs.get('blacklisted_ips')
        self.nameservers = kwargs.get('nameservers')
        self.permit_domains = kwargs.get('permit_domains')
        self.github_key = kwargs.get('github_key')
        self.github_user = kwargs.get('github_user')
        self.gitlab = kwargs.get('gitlab')
        self.alienvault = kwargs.get('alienvault')
        self.binaryedge = kwargs.get('binaryedge')
        self.c99 = kwargs.get('c99')
        self.censys_key = kwargs.get('censys_key')
        self.censys_secret = kwargs.get('censys_secret')
        self.chaos = kwargs.get('chaos')
        self.cloudflare = kwargs.get('cloudflare')
        self.circl_user = kwargs.get('circl_user')
        self.circl_pass = kwargs.get('circl_pass')
        self.dnsdb = kwargs.get('dnsdb')
        self.facebookct_key = kwargs.get('facebookct_key')
        self.facebookct_secret = kwargs.get('facebookct_secret')
        self.networksdb = kwargs.get('networksdb')
        self.recondev_free = kwargs.get('recondev_free')
        self.recondev_paid = kwargs.get('recondev_paid')
        self.passivetotal_key = kwargs.get('passivetotal_key')
        self.passivetotal_user = kwargs.get('passivetotal_user')
        self.securitytrails = kwargs.get('securitytrails')
        self.shodan = kwargs.get('shodan')
        self.spyse = kwargs.get('spyse')
        self.twitter_key = kwargs.get('twitter_key')
        self.twitter_secret = kwargs.get('twitter_secret')
        self.umbrella = kwargs.get('umbrella')
        self.urlscan = kwargs.get('urlscan')
        self.virustotal = kwargs.get('virustotal')
        self.whoisxml = kwargs.get('whoisxml')
        self.zetalytics = kwargs.get('zetalytics')
        self.zoomeye = kwargs.get('zoomeye')

class AccountConfigs(DatabaseIterators):
    def __init__(self):
        super().__init__('AccountConfig')

class Plan(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('plans', 'plan_id')
        self.plan_id = kwargs.get('plan_id')
        self.account_id = kwargs.get('account_id')
        self.name = kwargs.get('name')
        self.is_dedicated = bool(kwargs.get('is_dedicated', False))
        self.stripe_customer_id = kwargs.get('stripe_customer_id')
        self.stripe_product_id = kwargs.get('stripe_product_id')
        self.stripe_price_id = kwargs.get('stripe_price_id')
        self.stripe_subscription_id = kwargs.get('stripe_subscription_id')
        self.stripe_payment_method_id = kwargs.get('stripe_payment_method_id')
        self.stripe_card_brand = kwargs.get('stripe_card_brand')
        self.stripe_card_last4 = kwargs.get('stripe_card_last4')
        self.stripe_card_expiry_month = kwargs.get('stripe_card_expiry_month')
        self.stripe_card_expiry_year = kwargs.get('stripe_card_expiry_year')
        self.cost = Decimal(kwargs.get('cost', 0)).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        self.currency = kwargs.get('currency')
        self.retention_days = kwargs.get('retention_days', 32)
        self.active_daily = kwargs.get('active_daily', 1)
        self.scheduled_active_daily = kwargs.get('scheduled_active_daily', 0)
        self.passive_daily = kwargs.get('passive_daily', 10)
        self.scheduled_passive_daily = kwargs.get('scheduled_passive_daily', 0)
        self.git_integration_daily = kwargs.get('git_integration_daily', 0)
        self.source_code_daily = kwargs.get('source_code_daily', 0)
        self.dependency_support_rating = kwargs.get('dependency_support_rating', 0)
        self.alert_email = bool(kwargs.get('alert_email'))
        self.alert_integrations = bool(kwargs.get('alert_integrations'))
        self.threatintel = bool(kwargs.get('threatintel'))
        self.compromise_indicators = bool(kwargs.get('compromise_indicators'))
        self.typosquatting = bool(kwargs.get('typosquatting'))

    def __setattr__(self, name, value):
        if name in ['is_dedicated', 'alert_email', 'alert_integrations', 'threatintel', 'compromise_indicators', 'typosquatting']:
            value = bool(value)
        super().__setattr__(name, value)

class Plans(DatabaseIterators):
    def __init__(self):
        super().__init__('Plan')

class Role(DatabaseHelpers):
    ROLE_SUPPORT = 'Support'
    ROLE_SUPPORT_ID = 5
    ROLE_AUDIT = 'Audit'
    ROLE_AUDIT_ID = 4
    ROLE_RO = 'Read Only'
    ROLE_RO_ID = 3
    ROLE_BILLING = 'Billing'
    ROLE_BILLING_ID = 2
    ROLE_OWNER = 'Owner'
    ROLE_OWNER_ID = 1

    def __init__(self, **kwargs):
        super().__init__('roles', 'role_id')
        self.role_id = kwargs.get('role_id')
        self.name = kwargs.get('name')
        self.internal_only = bool(kwargs.get('internal_only', 0))

    def __setattr__(self, name, value):
        if name in ['internal_only']:
            value = bool(value)
        super().__setattr__(name, value)

class Roles(DatabaseIterators):
    def __init__(self):
        super().__init__('Role')

class Member(UserMixin, DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('members', 'member_id')
        self.member_id = kwargs.get('member_id')
        self.email = kwargs.get('email')
        self.account_id = kwargs.get('account_id')
        self.verified = bool(kwargs.get('verified'))
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
        super().__init__('Member')

class Invitation(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('invitations', 'invitation_id')
        self.invitation_id = kwargs.get('invitation_id')
        self.account_id = kwargs.get('account_id')
        self.invited_by_member_id = kwargs.get('invited_by_member_id')
        self.member_id = kwargs.get('member_id')
        self.role_id = kwargs.get('role_id')
        self.email = kwargs.get('email')
        self.confirmation_url = kwargs.get('confirmation_url')
        self.confirmation_sent = bool(kwargs.get('confirmation_sent'))
        self.message = kwargs.get('message')
        self.deleted = bool(kwargs.get('deleted'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['confirmation_sent', 'deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Invitations(DatabaseIterators):
    def __init__(self):
        super().__init__('Invitation')

class Subscriber(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('subscribers', 'subscriber_id')
        self.subscriber_id = kwargs.get('subscriber_id')
        self.email = kwargs.get('email')
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Subscribers(DatabaseIterators):
    def __init__(self):
        super().__init__('Subscriber')

class ActivityLog(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('activity_logs', 'activity_log_id')
        self.activity_log_id = kwargs.get('activity_log_id')
        self.member_id = kwargs.get('member_id')
        self.action = kwargs.get('action')
        self.description = kwargs.get('description')
        self.occurred = kwargs.get('occurred')

class ActivityLogs(DatabaseIterators):
    def __init__(self):
        super().__init__('ActivityLog')

class Notification(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('notifications', 'notification_id')
        self.notification_id = kwargs.get('notification_id')
        self.account_id = kwargs.get('account_id')
        self.description = kwargs.get('description')
        self.url = kwargs.get('url')
        self.marked_read = kwargs.get('marked_read')
        self.read_by = kwargs.get('read_by')
        self.created_at = kwargs.get('created_at')

class Notifications(DatabaseIterators):
    def __init__(self):
        super().__init__('Notification')

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

class KeyValue(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('key_values', 'key_value_id')
        self.key_value_id = kwargs.get('key_value_id')
        self.type = kwargs.get('type')
        self.key = kwargs.get('key')
        self.value = kwargs.get('value')
        self.hidden = bool(kwargs.get('hidden'))
        self.active_date = kwargs.get('active_date')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['hidden']:
            value = bool(value)
        super().__setattr__(name, value)

class KeyValues(DatabaseIterators):
    def __init__(self):
        super().__init__('KeyValue')

class Project(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('projects', 'project_id')
        self.project_id = kwargs.get('project_id')
        self.account_id = kwargs.get('account_id')
        self.name = kwargs.get('name')
        self.tracking_id = kwargs.get('tracking_id')
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['enabled', 'deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Projects(DatabaseIterators):
    def __init__(self):
        super().__init__('Project')

class Domain(DatabaseHelpers):
    _http_metadata = None
    stats = []

    def __init__(self, **kwargs):
        super().__init__('domains', 'domain_id')
        self.domain_id = kwargs.get('domain_id')
        self.parent_domain_id = kwargs.get('parent_domain_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.source = kwargs.get('source')
        self.name = kwargs.get('name')
        self.screenshot = bool(kwargs.get('screenshot'))
        self.schedule = kwargs.get('schedule')
        self.enabled = bool(kwargs.get('enabled'))
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['screenshot', 'verified', 'enabled', 'deleted']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_stats(self, latest_only=True):
        self.stats = []
        if latest_only:
            sql = "SELECT domain_stats_id FROM domain_stats WHERE domain_id = %(domain_id)s AND (created_at = (SELECT domain_value FROM domain_stats WHERE domain_stat = 'http_last_checked' AND domain_id = %(domain_id)s ORDER BY domain_value DESC LIMIT 1) OR domain_stat = 'http_last_checked')"
        else:
            sql = "SELECT domain_stats_id FROM domain_stats WHERE domain_id = %(domain_id)s ORDER BY created_at DESC"
        http_last_checked = None
        with mysql_adapter as database:
            results = database.query(sql, {'domain_id': self.domain_id}, cache_key=f'domain_stats/domain_id/{self.domain_id}')
            for val in results:
                domain_stat = DomainStat(domain_stats_id=val['domain_stats_id'])
                if domain_stat.hydrate():
                    self.stats.append(domain_stat)
                    if domain_stat.domain_stat == DomainStat.HTTP_LAST_CHECKED:
                        http_last_checked = domain_stat.domain_value
                        setattr(self, DomainStat.HTTP_LAST_CHECKED, http_last_checked)
        if http_last_checked:
            for domain_stat in self.stats:
                if domain_stat.created_at == http_last_checked:
                    setattr(self, domain_stat.domain_stat, domain_stat)

        return self

    def fetch_metadata(self):
        if not self.account_id or not self.domain_id or  not self.name:
            logger.warning('called Domain.fetch_metadata before initialising data')
            return self
        now = datetime.utcnow().replace(microsecond=0).isoformat()
        account = Account(account_id=self.account_id)
        account.hydrate()
        self._http_metadata = HTTPMetadata(f'http://{self.name}')
        self._http_metadata.head()
        self._http_metadata.url = f'https://{self.name}'
        self._http_metadata.head()\
            .verification_check()\
            .safe_browsing_check()\
            .phishtank_check()\
            .projecthoneypot()\
            .honeyscore_check()

        if self._http_metadata.signature_algorithm:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_SIGNATURE_ALGORITHM,
                domain_value=self._http_metadata.signature_algorithm,
                created_at=now
            ).persist()
        if self._http_metadata.negotiated_cipher:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_NEGOTIATED_CIPHER,
                domain_value=self._http_metadata.negotiated_cipher,
                created_at=now
            ).persist()
        if self._http_metadata.code:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_CODE,
                domain_value=self._http_metadata.code,
                domain_data=self._http_metadata.reason,
                created_at=now
            ).persist()
        if self._http_metadata.elapsed_duration:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_ELAPSED_DURATION,
                domain_value=self._http_metadata.elapsed_duration,
                created_at=now
            ).persist()
        if self._http_metadata.protocol_version:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_PROTOCOL,
                domain_value=self._http_metadata.protocol_version,
                created_at=now
            ).persist()
        if self._http_metadata.cookies:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_COOKIES,
                domain_data=json.dumps(self._http_metadata.cookies, default=str),
                created_at=now
            ).persist()
        if self._http_metadata.headers:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_HEADERS,
                domain_data=json.dumps(self._http_metadata.headers, default=str),
                created_at=now
            ).persist()
            for header_name, header_value in self._http_metadata.headers.items():
                if header_name == 'x-powered-by':
                    DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.APPLICATION_BANNER,
                        domain_value=header_value,
                        created_at=now
                    ).persist()
                if header_name == 'server':
                    DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.SERVER_BANNER,
                        domain_value=header_value,
                        created_at=now
                    ).persist()
                if header_name == 'via':
                    DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.APPLICATION_PROXY,
                        domain_value=header_value,
                        created_at=now
                    ).persist()

        if self._http_metadata.server_certificate:
            if self._http_metadata.sha1_fingerprint:
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SHA1_FINGERPRINT,
                    domain_value=self._http_metadata.sha1_fingerprint,
                    created_at=now
                ).persist()
            if self._http_metadata.server_key_size:
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SERVER_KEY_SIZE,
                    domain_value=self._http_metadata.server_key_size,
                    created_at=now
                ).persist()
            if self._http_metadata.pubkey_type:
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SERVER_KEY_TYPE,
                    domain_value=self._http_metadata.pubkey_type,
                    created_at=now
                ).persist()
            if self._http_metadata.server_certificate.get('serialNumber'):
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE,
                    domain_value=self._http_metadata.server_certificate.get('serialNumber'),
                    domain_data=self._http_metadata.server_certificate,
                    created_at=now
                ).persist()
            for issuer in self._http_metadata.server_certificate.get('issuer'):
                if issuer[0][0] == 'commonName':
                    DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUER,
                        domain_value=issuer[0][1],
                        created_at=now
                    ).persist()
                if issuer[0][0] == 'countryName':
                    DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUER_COUNTRY,
                        domain_value=issuer[0][1],
                        created_at=now
                    ).persist()
            if self._http_metadata.server_certificate.get('notBefore'):
                issued = datetime.strptime(self._http_metadata.server_certificate.get('notBefore'), HTTPMetadata.SSL_DATE_FMT)
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUED,
                    domain_value=issued.isoformat(),
                    domain_data=f'{(datetime.utcnow() - issued).days} days ago',
                    created_at=now
                ).persist()
            if self._http_metadata.server_certificate.get('notAfter'):
                expires = datetime.strptime(self._http_metadata.server_certificate.get('notAfter'), HTTPMetadata.SSL_DATE_FMT)
                DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_EXPIRY,
                    domain_value=expires.isoformat(),
                    domain_data=f'Expired {(datetime.utcnow() - expires).days} days ago' if expires < datetime.utcnow() else f'Valid for {(expires - datetime.utcnow()).days} days',
                    created_at=now
                ).persist()

        DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.DNS_REGISTERED,
            domain_value=1 if self._http_metadata.registered else 0,
            created_at=now
        ).persist()
        verified = bool(account.verification_hash == self._http_metadata.verification_hash)
        DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.APP_VERIFIED,
            domain_value=1 if verified else 0,
            created_at=now
        ).persist()
        if not self._http_metadata.registered:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.DNS_ANSWER,
                domain_value=self._http_metadata.dns_answer,
                created_at=now
            ).persist()

        if self._http_metadata.honey_score:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HONEY_SCORE,
                domain_value=self._http_metadata.honey_score,
                created_at=now
            ).persist()

        if self._http_metadata.threat_score:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.THREAT_SCORE,
                domain_value=self._http_metadata.threat_score,
                created_at=now
            ).persist()

        if self._http_metadata.threat_type:
            DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.THREAT_TYPE,
                domain_value=self._http_metadata.threat_type,
                created_at=now
            ).persist()

        phishtank_value = 'Unclassified'
        if self._http_metadata.phishtank:
            if self._http_metadata.phishtank.get('in_database'):
                phishtank_value = 'Reported Phish'
            elif self._http_metadata.phishtank.get('verified'):
                phishtank_value = 'Verified Phish'
        DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.PHISHTANK,
            domain_value=phishtank_value,
            domain_data=self._http_metadata.phishtank,
            created_at=now
        ).persist()

        sb_value = 'Safe'
        if self._http_metadata.safe_browsing:
            sb_value = f'{self._http_metadata.safe_browsing.get("platform_type")} {self._http_metadata.safe_browsing.get("threat_type")}'.lower()
        DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.SAFE_BROWSING,
            domain_value=sb_value,
            domain_data=self._http_metadata.safe_browsing,
            created_at=now
        ).persist()

        domain_stat = DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.HTTP_LAST_CHECKED,
        )
        domain_stat.hydrate(['domain_id', 'domain_stat'])
        domain_stat.domain_value = now
        domain_stat.persist(invalidations=[
            f'domain_stats/domain_id/{self.domain_id}'
        ])

        return self.get_stats()

class Domains(DatabaseIterators):
    def __init__(self):
        super().__init__('Domain')

class DomainStat(DatabaseHelpers):
    APP_VERIFIED = 'app_verified'
    APPLICATION_BANNER = 'application_banner'
    APPLICATION_PROXY = 'application_proxy'
    SERVER_BANNER = 'server_banner'
    SAFE_BROWSING = 'safe_browsing'
    HONEY_SCORE = 'honey_score'
    PHISHTANK = 'phishtank'
    THREAT_SCORE = 'threat_score'
    THREAT_TYPE = 'threat_type'
    HTTP_PROTOCOL = 'http_protocol'
    HTTP_NEGOTIATED_CIPHER = 'http_negotiated_cipher'
    HTTP_SIGNATURE_ALGORITHM = 'http_signature_algorithm'
    HTTP_SERVER_KEY_SIZE = 'http_server_key_size'
    HTTP_SHA1_FINGERPRINT = 'sha1_fingerprint'
    HTTP_SERVER_KEY_TYPE = 'http_server_key_type'
    HTTP_CERTIFICATE = 'http_certificate'
    HTTP_CERTIFICATE_ISSUER = 'http_certificate_issuer'
    HTTP_CERTIFICATE_ISSUER_COUNTRY = 'http_certificate_issuer_country'
    HTTP_CERTIFICATE_ISSUED = 'http_certificate_issued'
    HTTP_CERTIFICATE_EXPIRY = 'http_certificate_expiry'
    HTTP_CODE = 'http_code'
    HTTP_HEADERS = 'http_headers'
    HTTP_COOKIES = 'http_cookies'
    HTTP_ELAPSED_DURATION = 'http_elapsed_duration'
    HTTP_LAST_CHECKED = 'http_last_checked'
    HTML_TITLE = 'html_title'
    HTML_SIZE = 'html_size'
    DNS_REGISTERED = 'dns_registered'
    DNS_ANSWER = 'dns_answer'

    def __init__(self, **kwargs):
        super().__init__('domain_stats', 'domain_stats_id')
        self.domain_stats_id = kwargs.get('domain_stats_id')
        self.domain_id = kwargs.get('domain_id')
        self.domain_stat = kwargs.get('domain_stat')
        self.domain_value = kwargs.get('domain_value')
        self.domain_data = kwargs.get('domain_data')
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class DomainStats(DatabaseIterators):
    def __init__(self):
        super().__init__('DomainStat')

class Finding(DatabaseHelpers):
    CONFIDENCE_HIGH_RGB = [7, 189, 152]
    CONFIDENCE_MEDIUM_RGB = [15, 145, 119]
    CONFIDENCE_LOW_RGB = [0, 90, 72]
    SEVERITY_INFO_RGB = [103, 154, 255]
    SEVERITY_LOW_RGB = [53, 167, 30]
    SEVERITY_MEDIUM_RGB = [255, 183, 48]
    SEVERITY_HIGH_RGB = [255, 107, 48]
    SEVERITY_CRITICAL_RGB = [121, 18, 18]
    CRITICALITY_INFO_RGB = [44, 192, 255]
    CRITICALITY_LOW_RGB = [0, 162, 232]
    CRITICALITY_MEDIUM_RGB = [5, 100, 140]
    CRITICALITY_HIGH_RGB = [5, 72, 100]
    CRITICALITY_CRITICAL_RGB = [5, 48, 66]

    RATING_NONE = 'NOT SCORED'
    RATING_INFO = 'INFO'
    RATING_LOW = 'LOW'
    RATING_MEDIUM = 'MEDIUM'
    RATING_HIGH = 'HIGH'
    RATING_CRITICAL = 'CRITICAL'
    CONFIDENCE_HIGH = 'HIGH'
    CONFIDENCE_MEDIUM = 'MEDIUM'
    CONFIDENCE_LOW = 'LOW'
    WORKFLOW_NEW = 'NEW'
    WORKFLOW_ASSIGNED = 'ASSIGNED'
    WORKFLOW_IN_PROGRESS = 'IN_PROGRESS'
    WORKFLOW_RESOLVED = 'RESOLVED'
    WORKFLOW_DEFERRED = 'DEFERRED'
    WORKFLOW_DUPLICATE = 'DUPLICATE'
    WORKFLOW_MAP = {
        'DUPLICATE': 'Duplicate',
        'DEFERRED': 'Deferred',
        'RESOLVED': 'Resolved',
        'IN_PROGRESS': 'In Progress',
        'ASSIGNED': 'Assigned',
        'NEW': 'New',
    }
    VERIFY_UNKNOWN = 'UNKNOWN'
    VERIFY_TRUE_POSITIVE = 'TRUE_POSITIVE'
    VERIFY_FALSE_POSITIVE = 'FALSE_POSITIVE'
    VERIFY_BENIGN_POSITIVE = 'BENIGN_POSITIVE'
    VERIFY_MAP = {
        'UNKNOWN': 'Unknown',
        'BENIGN_POSITIVE': 'Not Vulnerable',
        'FALSE_POSITIVE': 'False Positive',
        'TRUE_POSITIVE': 'Vulnerable',
    }
    STATE_ACTIVE = 'ACTIVE'
    STATE_ARCHIVED = 'ARCHIVED'

    def __init__(self, **kwargs):
        super().__init__('findings', 'finding_id')
        self.finding_id = kwargs.get('finding_id')
        self.finding_detail_id = kwargs.get('finding_detail_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.assignee_id = kwargs.get('assignee_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.source_description = kwargs.get('source_description')
        self.is_passive = bool(kwargs.get('is_passive'))
        self.severity_normalized = kwargs.get('severity_normalized', 0)
        self.verification_state = kwargs.get('verification_state')
        self.workflow_state = kwargs.get('workflow_state')
        self.state = kwargs.get('state')
        self.evidence = kwargs.get('evidence')
        self.created_at = kwargs.get('created_at')
        self.updated_at = kwargs.get('updated_at')
        self.defer_to = kwargs.get('defer_to')
        self.last_observed_at = kwargs.get('last_observed_at')
        self.archived = bool(kwargs.get('archived'))
        self.notes = []
        self.watchers = []

    def __setattr__(self, name, value):
        if name in ['archived']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_watchers(self):
        sql = "SELECT member_id FROM finding_watchers WHERE finding_id = %(finding_id)s"
        with mysql_adapter as database:
            results = database.query(sql, {'finding_id': self.finding_id})
            for val in results:
                if not any(isinstance(x, Member) and x.member_id == val['member_id'] for x in self.watchers):
                    member = Member(member_id=val['member_id'])
                    if member.hydrate():
                        self.watchers.append(member)

        return self

    def add_watcher(self, member: Member)->bool:
        insert_stmt = "INSERT INTO finding_watchers (member_id, finding_id) VALUES (%(member_id)s, %(finding_id)s) ON DUPLICATE KEY UPDATE finding_id=finding_id;"
        with mysql_adapter as database:
            new_id = database.query(insert_stmt, {'member_id': member.member_id, 'finding_id': self.finding_id})
            if new_id:
                self.watchers.append(member)
                return True

        return False

    def get_notes(self):
        sql = "SELECT finding_note_id FROM finding_notes WHERE finding_id = %(finding_id)s"
        with mysql_adapter as database:
            results = database.query(sql, {'finding_id': self.finding_id})
            for val in results:
                if not any(isinstance(x, FindingNote) and x.finding_note_id == val['finding_note_id'] for x in self.notes):
                    note = FindingNote(finding_note_id=val['finding_note_id'])
                    if note.hydrate():
                        self.notes.append(note)

        return self

class Findings(DatabaseIterators):
    def __init__(self):
        super().__init__('Finding')

    def load_details(self):
        items = []
        for finding in self:
            detail = FindingDetail(finding_detail_id=finding.finding_detail_id)
            detail.hydrate()
            for col in detail.cols():
                setattr(finding, f'detail_{col}', getattr(detail, col))
            items.append(finding)
        self.set_items(items)
        return self

class FindingDetail(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('finding_details', 'finding_detail_id')
        self.finding_detail_id = kwargs.get('finding_detail_id')
        self.title = kwargs.get('title')
        self.description = kwargs.get('description')
        self.type_namespace = kwargs.get('type_namespace')
        self.type_category = kwargs.get('type_category')
        self.type_classifier = kwargs.get('type_classifier')
        self.criticality = kwargs.get('severity_product')
        self.confidence = kwargs.get('severity_product')
        self.severity_product = kwargs.get('severity_product')
        self.recommendation = kwargs.get('recommendation')
        self.recommendation_url = kwargs.get('recommendation_url')
        self.cvss_vector = kwargs.get('cvss_vector')
        self.created_at = kwargs.get('created_at')
        self.review = kwargs.get('review')
        self.updated_at = kwargs.get('updated_at')
        self.modified_by_id = kwargs.get('modified_by_id')

class FindingDetails(DatabaseIterators):
    def __init__(self):
        super().__init__('FindingDetail')

class FindingNote(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('finding_notes', 'finding_note_id')
        self.finding_note_id = kwargs.get('finding_note_id')
        self.finding_id = kwargs.get('finding_id')
        self.member_id = kwargs.get('member_id')
        self.text = kwargs.get('text')
        self.updated_at = kwargs.get('updated_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class FindingNotes(DatabaseIterators):
    def __init__(self):
        super().__init__('FindingNote')

class ServiceType(DatabaseHelpers):
    STATE_QUEUED = 'queued'
    STATE_STARTING = 'starting'
    STATE_PROCESSING = 'processing'
    STATE_COMPLETED = 'completed'
    STATE_ERROR = 'error'
    STATE_ABORT = 'aborted'
    STATE_FINALISING = 'finalising'

    def __init__(self, **kwargs):
        super().__init__('service_types', 'service_type_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.name = kwargs.get('name')
        self.category = kwargs.get('category')

class ServiceTypes(DatabaseIterators):
    def __init__(self):
        super().__init__('ServiceType')

class JobRun(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('job_runs', 'job_run_id')
        self.job_run_id = kwargs.get('job_run_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.tracking_id = kwargs.get('tracking_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.node_id = kwargs.get('node_id')
        self.worker_id = kwargs.get('worker_id')
        self.queue_data = kwargs.get('queue_data')
        self.state = kwargs.get('state')
        self.worker_message = kwargs.get('worker_message')
        self.priority = kwargs.get('priority', 0)
        self.created_at = kwargs.get('created_at')
        self.started_at = kwargs.get('started_at')
        self.updated_at = kwargs.get('updated_at')
        self.completed_at = kwargs.get('completed_at')

class JobRuns(DatabaseIterators):
    def __init__(self):
        super().__init__('JobRun')

    def query_json(self, search_filter: list, limit: int = 1, offset: int = 0, conditional = ' AND '):
        cache_key = None
        data = {}
        conditionals = []
        columns = JobRun().cols()
        for key, val in search_filter:
            if key in columns:
                if val is None:
                    conditionals.append(f' {key} is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditionals.append(f' {key} in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditionals.append(f' {key} = %({key})s ')
            else:
                placeholder = ''.join(choice(ascii_lowercase) for _ in range(8))
                data[placeholder] = val
                conditionals.append(f" JSON_EXTRACT(queue_data, '{key}') = %({placeholder})s ")
        where = conditional.join(conditionals)
        sql = f"SELECT * FROM job_runs WHERE {where} LIMIT {offset},{limit}"
        with mysql_adapter as database:
            results = database.query(sql, data)
            self._load_items(results)

        return self

class DnsRecord(DatabaseHelpers):
    RECORDS = {
        'A': 'a host address  [RFC1035]',
        'NS': 'an authoritative name server  [RFC1035]',
        'MD': 'a mail destination (OBSOLETE - use MX)  [RFC1035]',
        'MF': 'a mail forwarder (OBSOLETE - use MX)  [RFC1035]',
        'CNAME': 'the canonical name for an alias  [RFC1035]',
        'SOA': 'marks the start of a zone of authority  [RFC1035]',
        'MB': 'a mailbox domain name (EXPERIMENTAL)  [RFC1035]',
        'MG': 'a mail group member (EXPERIMENTAL)  [RFC1035]',
        'MR': 'a mail rename domain name (EXPERIMENTAL)  [RFC1035]',
        'NULL': 'a null RR (EXPERIMENTAL)  [RFC1035]',
        'WKS': 'a well known service description  [RFC1035]',
        'PTR': 'a domain name pointer  [RFC1035]',
        'HINFO': 'host information  [RFC1035]',
        'MINFO': 'mailbox or mail list information  [RFC1035]',
        'MX': 'mail exchange  [RFC1035]',
        'TXT': 'text strings  [RFC1035]',
        'RP': 'for Responsible Person  [RFC1183]',
        'AFSDB': 'for AFS Data Base location  [RFC1183][RFC5864]',
        'X25': 'for X.25 PSDN address  [RFC1183]',
        'ISDN': 'for ISDN address  [RFC1183]',
        'RT': 'for Route Through  [RFC1183]',
        'NSAP': 'for NSAP address, NSAP style A record  [RFC1706]',
        'NSAP-PTR': 'for domain name pointer, NSAP style  [RFC1348][RFC1637][RFC1706]',
        'SIG': 'for security signature  [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]',
        'KEY': 'for security key  [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]',
        'PX': 'X.400 mail mapping information  [RFC2163]',
        'GPOS': 'Geographical Position  [RFC1712]',
        'AAAA': 'IP6 Address  [RFC3596]',
        'LOC': 'Location Information  [RFC1876]',
        'NXT': 'Next Domain (OBSOLETE)  [RFC3755][RFC2535]',
        'EID': 'Endpoint Identifier  [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]',
        'NIMLOC': 'Nimrod Locator  [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]',
        'SRV': 'Server Selection  [1][RFC2782]',
        'ATMA': 'ATM Address  [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]',
        'NAPTR': 'Naming Authority Pointer  [RFC2915][RFC2168][RFC3403]',
        'KX': 'Key Exchanger  [RFC2230]',
        'CERT': 'CERT  [RFC4398]',
        'A6': 'A6 (OBSOLETE - use AAAA)  [RFC3226][RFC2874][RFC6563]',
        'DNAME': 'DNAME  [RFC6672]',
        'SINK': 'SINK  [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]',
        'OPT': 'OPT  [RFC6891][RFC3225]',
        'APL': 'APL  [RFC3123]',
        'DS': 'Delegation Signer  [RFC4034][RFC3658]',
        'SSHFP': 'SSH KeyFindings Fingerprint  [RFC4255]',
        'IPSECKEY': 'IPSECKEY  [RFC4025]',
        'RRSIG': 'RRSIG  [RFC4034][RFC3755]',
        'NSEC': 'NSEC  [RFC4034][RFC3755]',
        'DNSKEY': 'DNSKEY  [RFC4034][RFC3755]',
        'DHCID': 'DHCID  [RFC4701]',
        'NSEC3': 'NSEC3  [RFC5155]',
        'NSEC3PARAM': 'NSEC3PARAM  [RFC5155]',
        'TLSA': 'TLSA  [RFC6698]',
        'SMIMEA': 'S/MIME cert association  [RFC8162]',
        'HIP': 'Host Identity Protocol  [RFC8005]',
        'NINFO': 'NINFO  [Jim_Reid]',
        'RKEY': 'RKEY  [Jim_Reid]',
        'TALINK': 'Trust FindingsAnchor LINK  [Wouter_Wijngaards]',
        'CDS': 'Child DS  [RFC7344]',
        'CDNSKEY': 'DNSKEY(s) the Child wants reflected in DS  [RFC7344]',
        'OPENPGPKEY': 'OpenPGP Key  [RFC7929]',
        'CSYNC': 'Child-To-Parent Synchronization  [RFC7477]',
        'ZONEMD': 'message digest for DNS zone  [draft-wessels-dns-zone-digest]',
        'SPF': '[RFC7208]',
        'UINFO': '[IANA-Reserved]',
        'UID': '[IANA-Reserved]',
        'GID': '[IANA-Reserved]',
        'UNSPEC': '[IANA-Reserved]',
        'NID': '[RFC6742]',
        'L32': '[RFC6742]',
        'L64': '[RFC6742]',
        'LP': '[RFC6742]',
        'EUI48': 'an EUI-48 address  [RFC7043]',
        'EUI64': 'an EUI-64 address  [RFC7043]',
        'TKEY': 'Transaction Key  [RFC2930]',
        'TSIG': 'Transaction Signature  [RFC2845]',
        'IXFR': 'incremental transfer  [RFC1995]',
        'AXFR': 'transfer of an entire zone  [RFC1035][RFC5936]',
        'MAILB': 'mailbox-related RRs (MB, MG or MR)  [RFC1035]',
        'MAILA': 'mail agent RRs (OBSOLETE - see MX)  [RFC1035]',
        '*': 'A request for some or all records the server has available  [RFC1035][RFC6895][RFC8482]',
        'URI': 'URI  [RFC7553]',
        'CAA': 'Certification Authority Restriction  [RFC8659]',
        'AVC': 'Application Visibility and Control  [Wolfgang_Riedel]',
        'DOA': 'Digital Object Architecture  [draft-durand-doa-over-dns]',
        'AMTRELAY': 'Automatic Multicast Tunneling Relay  [draft-ietf-mboned-driad-amt-discovery]',
        'TA': 'DNSSEC Trust Authorities  [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]',
        'DLV': 'DNSSEC Lookaside Validation (OBSOLETE)  [RFC-ietf-dnsop-obsolete-dlv-02][RFC4431]'
    }
    def __init__(self, **kwargs):
        super().__init__('dns_records', 'dns_record_id')
        self.dns_record_id = kwargs.get('dns_record_id')
        self.domain_id = kwargs.get('domain_id')
        self.ttl = kwargs.get('ttl')
        self.dns_class = kwargs.get('dns_class')
        self.resource = kwargs.get('resource')
        self.answer = kwargs.get('answer')
        self.raw = kwargs.get('raw')
        self.last_checked = kwargs.get('last_checked')

class DnsRecords(DatabaseIterators):
    def __init__(self):
        super().__init__('DnsRecord')

class Program(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('programs', 'program_id')
        self.program_id = kwargs.get('program_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.name = kwargs.get('name')
        self.version = kwargs.get('version')
        self.source_description = kwargs.get('source_description')
        self.external_url = kwargs.get('external_url')
        self.icon_url = kwargs.get('icon_url')
        self.category = kwargs.get('category')
        self.created_at = kwargs.get('created_at')
        self.last_checked = kwargs.get('last_checked')

class Programs(DatabaseIterators):
    def __init__(self):
        super().__init__('Program')

class SecurityAlert(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('security_alerts', 'security_alert_id')
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

class SecurityAlerts(DatabaseIterators):
    def __init__(self):
        super().__init__('SecurityAlert')

class KnownIp(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('known_ips', 'known_ip_id')
        self.known_ip_id = kwargs.get('known_ip_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.ip_address = kwargs.get('ip_address')
        self.ip_version = kwargs.get('ip_version')
        self.source = kwargs.get('source')
        self.asn_code = kwargs.get('asn_code')
        self.asn_name = kwargs.get('asn_name')
        self.updated_at = kwargs.get('updated_at')

class KnownIps(DatabaseIterators):
    def __init__(self):
        super().__init__('KnownIp')

class Feed(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('feeds', 'feed_id')
        self.feed_id = kwargs.get('feed_id')
        self.name = kwargs.get('name')
        self.category = kwargs.get('category')
        self.description = kwargs.get('description')
        self.url = kwargs.get('url')
        self.type = kwargs.get('type')
        self.method = kwargs.get('method')
        self.username = kwargs.get('username')
        self.credential_key = kwargs.get('credential_key')
        self.http_status = kwargs.get('http_status')
        self.http_code = kwargs.get('http_code')
        self.alert_title = kwargs.get('alert_title')
        self.schedule = kwargs.get('schedule')
        self.feed_site = kwargs.get('feed_site')
        self.abuse_email = kwargs.get('abuse_email')
        self.disabled = bool(kwargs.get('disabled'))
        self.start_check = kwargs.get('start_check')
        self.last_checked = kwargs.get('last_checked')

    def __setattr__(self, name, value):
        if name in ['disabled']:
            value = bool(value)
        super().__setattr__(name, value)

class Feeds(DatabaseIterators):
    def __init__(self):
        super().__init__('Feed')

    def num_running(self, category: str) -> int:
        with mysql_adapter as database:
            results = database.query_one(f"""SELECT count(*) as num FROM feeds WHERE
                category = %(category)s AND
                start_check IS NOT NULL AND
                last_checked IS NOT NULL AND
                start_check > last_checked
                """, {'category': category})
            return int(results['num'])
        return 0

    def num_errored(self, category: str) -> int:
        with mysql_adapter as database:
            results = database.query_one(f"""SELECT count(*) as num FROM feeds WHERE
                category = %(category)s AND
                http_code = 200
                """, {'category': category})
            return int(results['num'])
        return 0

    def num_queued(self, category: str) -> int:
        return len(self.get_queued(category, 1000))

    def get_queued(self, category: str, limit: int = 10) -> list:
        ret = []
        data = {
            'category': category,
            'hourly': datetime.utcnow() - timedelta(hours=1),
            'daily': datetime.utcnow() - timedelta(days=1),
            'monthly': datetime.utcnow() - timedelta(weeks=4),
        }
        with mysql_adapter as database:
            results = database.query(f"""SELECT * FROM feeds WHERE
                category = %(category)s AND
                start_check IS NULL OR
                last_checked IS NULL OR
                (schedule = 'hourly' AND last_checked < %(hourly)s) OR
                (schedule = 'daily' AND last_checked < %(daily)s) OR
                (schedule = 'monthly' AND last_checked < %(monthly)s)
                ORDER BY start_check ASC
                LIMIT {limit}""", data)

            shuffle(results)
            for result in results:
                feed = Feed()
                for col, val in result.items():
                    setattr(feed, col, val)
                ret.append(feed)

        return ret
