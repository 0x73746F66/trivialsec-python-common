from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.account_config'
__table__ = 'account_config'
__pk__ = 'account_id'

class AccountConfig(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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
        super().__init__('AccountConfig', __table__, __pk__)
