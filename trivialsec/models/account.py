from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.account'

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
