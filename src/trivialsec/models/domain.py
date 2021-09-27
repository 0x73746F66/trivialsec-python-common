from gunicorn.glogging import logging
from trivialsec.helpers.elasticsearch_adapter import Elasticsearch_Document_Adapter, Elasticsearch_Collection_Adapter
from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.domain'
__index__ = 'domains'
__table__ = 'domain_monitoring'
__pk__ = 'domain_monitoring_id'
logger = logging.getLogger(__name__)

class Domain(Elasticsearch_Document_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__index__, 'domain_name')
        self.domain_name = kwargs.get('domain_name')
        self.apex = kwargs.get('apex')
        self.tld = kwargs.get('tld')
        self.source = kwargs.get('source')
        self.txt_verification = kwargs.get('txt_verification')
        self.asn = kwargs.get('asn')
        self.dns_registered = bool(kwargs.get('dns_registered'))
        self.dns_answer = kwargs.get('dns_answer')
        self.dns_transfer_allowed = bool(kwargs.get('dns_transfer_allowed'))
        self.screenshot = bool(kwargs.get('screenshot'))
        self.assessed_at = kwargs.get('assessed_at')
        self.registered_at = kwargs.get('registered_at')
        self.registrar = kwargs.get('registrar')
        self.registrant = kwargs.get('registrant')
        self.reputation_whoisxmlapi = kwargs.get('reputation_whoisxmlapi')
        self.reputation_domaintools = kwargs.get('reputation_domaintools')
        self.reputation_google_safe_browsing = kwargs.get('reputation_google_safe_browsing')
        self.tls_extensions = kwargs.get('tls_extensions', [])
        self.etls = bool(kwargs.get('etls'))
        self.session_id = bool(kwargs.get('session_id'))
        self.session_resumption_id = bool(kwargs.get('session_resumption_id'))
        self.session_resumption_tickets = bool(kwargs.get('session_resumption_tickets'))
        self.clock_skew_fingerprinting = bool(kwargs.get('clock_skew_fingerprinting'))
        self.requires_client_authentication = bool(kwargs.get('requires_client_authentication'))
        self.requires_client_mutual_tls = bool(kwargs.get('requires_client_mutual_tls'))
        self.rfc5077_hint = kwargs.get('rfc5077_hint')
        self.valid_dmarc = bool(kwargs.get('valid_dmarc'))
        self.dmarc_reject = bool(kwargs.get('dmarc_reject'))
        self.dmarc_quarantine = bool(kwargs.get('dmarc_quarantine'))
        self.valid_spf = bool(kwargs.get('valid_spf'))
        self.dns_records = kwargs.get('dns_records', {})
        self.http_status = kwargs.get('http_status')
        self.html_size = kwargs.get('html_size')
        self.html_title = kwargs.get('html_title')
        self.server_banner = kwargs.get('server_banner')
        self.application_banner = kwargs.get('application_banner')
        self.reverse_proxy_banner = kwargs.get('reverse_proxy_banner')
        self.http_headers = kwargs.get('http_headers', [])
        self.cookies = kwargs.get('cookies', [])
        self.browser_simulations = kwargs.get('browser_simulations', [])
        self.javascript = kwargs.get('javascript', [])
        self.scanner_dependency_check = bool(kwargs.get('scanner_dependency_check'))
        self.scanner_nikto2 = bool(kwargs.get('scanner_nikto2'))
        self.scanner_owasp_zap = bool(kwargs.get('scanner_owasp_zap'))
        self.scanner_npm_audit = bool(kwargs.get('scanner_npm_audit'))
        self.scanner_semgrep_r2c_ci = bool(kwargs.get('scanner_semgrep_r2c_ci'))
        self.scanner_semgrep_command_injection = bool(kwargs.get('scanner_semgrep_command_injection'))
        self.scanner_semgrep_insecure_transport = bool(kwargs.get('scanner_semgrep_insecure_transport'))
        self.scanner_semgrep_jwt = bool(kwargs.get('scanner_semgrep_jwt'))
        self.scanner_semgrep_secrets = bool(kwargs.get('scanner_semgrep_secrets'))
        self.scanner_semgrep_r2c_security_audit = bool(kwargs.get('scanner_semgrep_r2c_security_audit'))
        self.scanner_semgrep_minusworld_ruby_on_rails_xss = bool(kwargs.get('scanner_semgrep_minusworld_ruby_on_rails_xss'))
        self.scanner_semgrep_nodejsscan = bool(kwargs.get('scanner_semgrep_nodejsscan'))
        self.scanner_semgrep_react = bool(kwargs.get('scanner_semgrep_react'))
        self.scanner_semgrep_javascript = bool(kwargs.get('scanner_semgrep_javascript'))
        self.scanner_semgrep_ruby = bool(kwargs.get('scanner_semgrep_ruby'))
        self.scanner_semgrep_golang = bool(kwargs.get('scanner_semgrep_golang'))
        self.scanner_semgrep_gosec = bool(kwargs.get('scanner_semgrep_gosec'))
        self.scanner_semgrep_docker_compose = bool(kwargs.get('scanner_semgrep_docker_compose'))
        self.scanner_semgrep_dockerfile = bool(kwargs.get('scanner_semgrep_dockerfile'))
        self.scanner_semgrep_findsecbugs = bool(kwargs.get('scanner_semgrep_findsecbugs'))
        self.scanner_semgrep_bandit = bool(kwargs.get('scanner_semgrep_bandit'))
        self.scanner_semgrep_eslint_plugin_security = bool(kwargs.get('scanner_semgrep_eslint_plugin_security'))
        self.scanner_ossaudit = bool(kwargs.get('scanner_ossaudit'))
        self.scanner_joomla = bool(kwargs.get('scanner_joomla'))
        self.scanner_wordpress = bool(kwargs.get('scanner_wordpress'))
        self.scanner_network = bool(kwargs.get('scanner_network'))
        self.scanner_subdomains = bool(kwargs.get('scanner_subdomains'))
        self.scanner_crawler = bool(kwargs.get('scanner_crawler'))
        self.scanner_file_protocols = bool(kwargs.get('scanner_file_protocols'))
        self.scanner_git = bool(kwargs.get('scanner_git'))
        self.scanner_orphaned_files = bool(kwargs.get('scanner_orphaned_files'))
        self.scanner_dsstore = bool(kwargs.get('scanner_dsstore'))
        self.scanner_secret_strings = bool(kwargs.get('scanner_secret_strings'))
        self.scanner_starttls_bugs = bool(kwargs.get('scanner_starttls_bugs'))
        self.scanner_compression_bugs = bool(kwargs.get('scanner_compression_bugs'))
        self.scanner_ldap = bool(kwargs.get('scanner_ldap'))
        self.scanner_kerberoaster = bool(kwargs.get('scanner_kerberoaster'))
        self.scanner_saas_takeover = bool(kwargs.get('scanner_saas_takeover'))
        self.scanner_subdomain_takeover = bool(kwargs.get('scanner_subdomain_takeover'))
        self.scanner_dns_fronting = bool(kwargs.get('scanner_dns_fronting'))
        self.scanner_cname_collusion = bool(kwargs.get('scanner_cname_collusion'))
        self.scanner_vpn_detect = bool(kwargs.get('scanner_vpn_detect'))
        self.scanner_popped_shells = bool(kwargs.get('scanner_popped_shells'))
        self.scanner_anti_bruteforce = bool(kwargs.get('scanner_anti_bruteforce'))
        self.scanner_brand_protection = bool(kwargs.get('scanner_brand_protection'))
        self.scanner_xss_tester = bool(kwargs.get('scanner_xss_tester'))
        self.scanner_reflected_ddos = bool(kwargs.get('scanner_reflected_ddos'))
        self.scanner_request_smuggler = bool(kwargs.get('scanner_request_smuggler'))
        self.scanner_dce_rpc = bool(kwargs.get('scanner_dce_rpc'))
        self.scanner_http_desync = bool(kwargs.get('scanner_http_desync'))
        self.scanner_oauth2_checker = bool(kwargs.get('scanner_oauth2_checker'))
        self.scanner_saml_injection = bool(kwargs.get('scanner_saml_injection'))
        self.scanner_pwnedkeys_com = bool(kwargs.get('scanner_pwnedkeys_com'))
        self.intel_labs_snort_org = bool(kwargs.get('intel_labs_snort_org'))
        self.intel_dataplane_org = bool(kwargs.get('intel_dataplane_org'))
        self.intel_isc_sans_intelfeed = bool(kwargs.get('intel_isc_sans_intelfeed'))
        self.intel_abuseipdb = bool(kwargs.get('intel_abuseipdb'))
        self.intel_spamhaus = bool(kwargs.get('intel_spamhaus'))
        self.intel_phishtank = bool(kwargs.get('intel_phishtank'))
        self.intel_binarydefense = bool(kwargs.get('intel_binarydefense'))
        self.intel_emergingthreats_fwrules = bool(kwargs.get('intel_emergingthreats_fwrules'))
        self.intel_honey_score = kwargs.get('intel_honey_score')
        self.intel_threat_score = kwargs.get('intel_threat_score')
        self.intel_threat_type = kwargs.get('intel_threat_type')
        self.intel_hibp_exposure = bool(kwargs.get('intel_hibp_exposure'))
        self.intel_malc0de = bool(kwargs.get('intel_malc0de'))
        self.intel_crtsh = bool(kwargs.get('intel_crtsh'))
        self.intel_c2_callbackdomains = bool(kwargs.get('intel_c2_callbackdomains'))
        self.intel_sorbs = bool(kwargs.get('intel_sorbs'))
        self.intel_tor_exit_nodes = bool(kwargs.get('intel_tor_exit_nodes'))
        self.intel_disposable_email_domain = bool(kwargs.get('intel_disposable_email_domains'))
        self.protocol_sslv2 = bool(kwargs.get('protocol_sslv2'))
        self.protocol_sslv3 = bool(kwargs.get('protocol_sslv3'))
        self.protocol_tls1_0 = bool(kwargs.get('protocol_tls1_0'))
        self.protocol_tls1_1 = bool(kwargs.get('protocol_tls1_1'))
        self.protocol_tls1_2 = bool(kwargs.get('protocol_tls1_2'))
        self.protocol_tls1_3 = bool(kwargs.get('protocol_tls1_3'))
        self.protocol_spdy = kwargs.get('protocol_spdy')
        self.protocol_http2 = kwargs.get('protocol_http2')
        self.negotiated_protocol = kwargs.get('negotiated_protocol')
        self.negotiated_key_exchange = kwargs.get('negotiated_key_exchange')
        self.negotiated_cipher_suite_iana = kwargs.get('negotiated_cipher_suite_iana')
        self.negotiated_cipher_suite_openssl = kwargs.get('negotiated_cipher_suite_openssl')
        self.signature_algorithm = kwargs.get('signature_algorithm')
        self.sha1_fingerprint = kwargs.get('sha1_fingerprint')
        self.certificate_serial_number = kwargs.get('certificate_serial_number')
        self.server_key_size = kwargs.get('server_key_size')
        self.server_cipher_order = kwargs.get('server_cipher_order')
        self.pubkey_type = kwargs.get('pubkey_type')
        self.certificate_valid = bool(kwargs.get('certificate_valid'))
        self.certificate_validation_result = kwargs.get('certificate_validation_result')
        self.certificate_is_self_signed = kwargs.get('certificate_is_self_signed')
        self.certificate_issuer = kwargs.get('certificate_issuer')
        self.certificate_issuer_country = kwargs.get('certificate_issuer_country')
        self.certificate_not_before = kwargs.get('certificate_not_before')
        self.certificate_not_after = kwargs.get('certificate_not_after')
        self.certificate_chain_trust = bool(kwargs.get('certificate_chain_trust'))
        self.certificate_chain_valid = bool(kwargs.get('certificate_chain_valid'))
        self.certificate_chain_validation_result = kwargs.get('certificate_chain_validation_result')
        self.offered_cipher_suite_groups = kwargs.get('offered_cipher_suite_groups')
        self.cipher_suite_group_pfs = bool(kwargs.get('cipher_suite_group_pfs'))
        self.cipher_suite_group_aead = bool(kwargs.get('cipher_suite_group_aead'))
        self.cipher_suite_group_obsoleted = bool(kwargs.get('cipher_suite_group_obsoleted'))
        self.cipher_suite_group_3des = bool(kwargs.get('cipher_suite_group_3des'))
        self.cipher_suite_group_des = bool(kwargs.get('cipher_suite_group_des'))
        self.cipher_suite_group_export = bool(kwargs.get('cipher_suite_group_export'))
        self.cipher_suite_group_anon = bool(kwargs.get('cipher_suite_group_anon'))
        self.cipher_suite_group_null = bool(kwargs.get('cipher_suite_group_null'))
        self.offered_protocols = kwargs.get('offered_protocols', [])
        self.certificates = kwargs.get('certificates', [])
        self.trust_store_mozilla = bool(kwargs.get('trust_store_mozilla'))
        self.trust_store_apple = bool(kwargs.get('trust_store_apple'))
        self.trust_store_android = bool(kwargs.get('trust_store_android'))
        self.trust_store_java = bool(kwargs.get('trust_store_java'))
        self.trust_store_windows = bool(kwargs.get('trust_store_windows'))
        self.extended_validation = bool(kwargs.get('extended_validation'))
        self.certification_authority_authorization = bool(kwargs.get('certification_authority_authorization'))
        self.revocation_ocsp_url = kwargs.get('revocation_ocsp_url')
        self.revocation_ocsp_crl = kwargs.get('revocation_ocsp_must_staple')
        self.revocation_ocsp_revoked = bool(kwargs.get('revocation_ocsp_url'))
        self.revocation_ocsp_stapling = bool(kwargs.get('revocation_ocsp_stapling'))
        self.revocation_ocsp_must_staple = bool(kwargs.get('revocation_ocsp_must_staple'))
        self.certificate_transparency = kwargs.get('certificate_transparency', [])
        self.phishing_domains = kwargs.get('phishing_domains', [])
        self.breaches = kwargs.get('breaches', [])

    def __setattr__(self, name, value):
        if name in [
            'dns_registered',
            'dns_transfer_allowed',
            'screenshot',
            'etls',
            'session_id',
            'session_resumption_id',
            'session_resumption_tickets',
            'clock_skew_fingerprinting',
            'requires_client_authentication',
            'requires_client_mutual_tls',
            'valid_dmarc',
            'dmarc_reject',
            'dmarc_quarantine',
            'valid_spf',
            'scanner_dependency_check',
            'scanner_nikto2',
            'scanner_owasp_zap',
            'scanner_npm_audit',
            'scanner_semgrep_r2c_ci',
            'scanner_semgrep_command_injection',
            'scanner_semgrep_insecure_transport',
            'scanner_semgrep_jwt',
            'scanner_semgrep_secrets',
            'scanner_semgrep_r2c_security_audit',
            'scanner_semgrep_minusworld.ruby_on_rails_xss',
            'scanner_semgrep_nodejsscan',
            'scanner_semgrep_react',
            'scanner_semgrep_javascript',
            'scanner_semgrep_ruby',
            'scanner_semgrep_golang',
            'scanner_semgrep_gosec',
            'scanner_semgrep_docker_compose',
            'scanner_semgrep_dockerfile',
            'scanner_semgrep_findsecbugs',
            'scanner_semgrep_bandit',
            'scanner_semgrep_eslint_plugin_security',
            'scanner_ossaudit',
            'scanner_joomla',
            'scanner_wordpress',
            'scanner_network',
            'scanner_subdomains',
            'scanner_crawler',
            'scanner_file_protocols',
            'scanner_git',
            'scanner_orphaned_files',
            'scanner_DSStore',
            'scanner_secret_strings',
            'scanner_starttls_bugs',
            'scanner_compression_bugs',
            'scanner_ldap',
            'scanner_kerberoaster',
            'scanner_saas_takeover',
            'scanner_subdomain_takeover',
            'scanner_dns_fronting',
            'scanner_cname_collusion',
            'scanner_vpn_detect',
            'scanner_popped_shells',
            'scanner_anti_bruteforce',
            'scanner_brand_protection',
            'scanner_xss_tester',
            'scanner_reflected_ddos',
            'scanner_request_smuggler',
            'scanner_dce_rpc',
            'scanner_http_desync',
            'scanner_saml_injection',
            'scanner_pwnedkeys.com',
            'intel_labs.snort.org',
            'intel_dataplane.org',
            'intel_isc_sans_intelfeed',
            'intel_abuseipdb',
            'intel_spamhaus',
            'intel_phishtank',
            'intel_binarydefense',
            'intel_emergingthreats_fwrules',
            'intel_hibp_exposure',
            'intel_malc0de',
            'intel_crtsh',
            'intel_c2_callbackdomains',
            'intel_sorbs',
            'intel_tor_exit_nodes',
            'intel_disposable_email_domain',
            'protocol_sslv2',
            'protocol_sslv3',
            'protocol_tls1.0',
            'protocol_tls1.1',
            'protocol_tls1.2',
            'protocol_tls1.3',
            'cipher_suite_group_pfs',
            'cipher_suite_group_aead',
            'cipher_suite_group_obsoleted',
            'cipher_suite_group_3des',
            'cipher_suite_group_des',
            'cipher_suite_group_export',
            'cipher_suite_group_anon',
            'cipher_suite_group_null',
            'trust_store_mozilla',
            'trust_store_apple',
            'trust_store_android',
            'trust_store_java',
            'trust_store_windows',
            'extended_validation',
            'certification_authority_authorization',
            'certificate_chain_trust',
            'certificate_chain_valid',
            'certificate_valid',
            'revocation_ocsp_url',
            'revocation_ocsp_crl',
            'revocation_ocsp_revoked',
            'revocation_ocsp_stapling',
            'revocation_ocsp_must_staple']:
            value = bool(value)
        super().__setattr__(name, value)

class Domains(Elasticsearch_Collection_Adapter):
    def __init__(self):
        super().__init__('DomainDoc', __index__, 'domain_name')

class DomainMonitor(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.domain_monitoring_id = kwargs.get(__pk__)
        self.domain_name = kwargs.get('domain_name')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.schedule = kwargs.get('schedule')
        self.enabled = bool(kwargs.get('enabled'))
        self.created_at = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['enabled']:
            value = bool(value)
        super().__setattr__(name, value)

class DomainMonitoring(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('DomainMonitor', __table__, __pk__)
