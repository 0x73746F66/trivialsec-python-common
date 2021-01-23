from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.known_ip'

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
