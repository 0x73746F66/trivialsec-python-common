from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.domain_stat'
__table__ = 'domain_stats'
__pk__ = 'domain_stats_id'

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
    HTTP_CERTIFICATE_IS_SELF_SIGNED = 'http_certificate_is_self_signed'
    HTTP_CERTIFICATE_ERROR = 'http_certificate_error'
    HTTP_CODE = 'http_code'
    HTTP_HEADERS = 'http_headers'
    HTTP_COOKIES = 'http_cookies'
    HTTP_ELAPSED_DURATION = 'http_elapsed_duration'
    HTTP_LAST_CHECKED = 'http_last_checked'
    HTML_TITLE = 'html_title'
    HTML_SIZE = 'html_size'
    DNS_REGISTERED = 'dns_registered'
    DNS_ANSWER = 'dns_answer'
    HIBP_BREACH = 'hibp_breach'
    HIBP_EXPOSURE = 'hibp_exposure'
    HIBP_DISCLOSURE = 'hibp_disclosure'
    PHISH_DOMAIN = 'phish_domain'
    DOMAIN_REPUTATION = 'domain_reputation'
    DOMAIN_REGISTRATION = 'domain_registration'

    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.domain_stats_id = kwargs.get('domain_stats_id')
        self.domain_id = kwargs.get('domain_id')
        self.domain_stat = kwargs.get('domain_stat')
        self.domain_value = kwargs.get('domain_value')
        self.domain_data = kwargs.get('domain_data')
        self.created_at = kwargs.get('created_at')

class DomainStats(DatabaseIterators):
    def __init__(self):
        super().__init__('DomainStat', __table__, __pk__)
