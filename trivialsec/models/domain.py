import json
import socket
from ssl import create_default_context, _create_unverified_context, SSLCertVerificationError, Purpose
from datetime import datetime
from OpenSSL.crypto import X509, X509Name
from gunicorn.glogging import logging
from trivialsec.helpers.elasticsearch_adapter import Elasticsearch_Document_Adapter, Elasticsearch_Collection_Adapter
from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter, replica_adapter
from trivialsec.helpers.transport import Metadata
from .account import Account
from .domain_stat import DomainStat



__module__ = 'trivialsec.models.domain'
__table__ = 'domains'
__pk__ = 'domain_id'
__index__ = 'domains'
logger = logging.getLogger(__name__)

class DomainDoc(Elasticsearch_Document_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__index__, 'domain_name')
        self.domain_name = kwargs.get('domain_name')
        self.apex = kwargs.get('apex')
        self.tld = kwargs.get('tld')
        self.asn = kwargs.get('asn')
        self.dns_registered = bool(kwargs.get('dns_registered'))
        self.screenshot = bool(kwargs.get('screenshot'))
        self.assessed_at = kwargs.get('assessed_at')
        self.registered_at = kwargs.get('registered_at')
        self.registrar = kwargs.get('registrar')
        self.registrant = kwargs.get('registrant')
        self.registrar_history = kwargs.get('registrar_history', [])
        self.reputation = kwargs.get('reputation')
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
        self.server_banner = kwargs.get('server_banner')
        self.application_banner = kwargs.get('application_banner')
        self.reverse_proxy_banner = kwargs.get('reverse_proxy_banner')
        self.http_headers = kwargs.get('http_headers', [])
        self.browser_simulations = kwargs.get('browser_simulations', [])
        self.javascript = kwargs.get('javascript', [])
        self.other_docstrings = kwargs.get('other_docstrings', [])
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
        self.scanner_oidc_authz = bool(kwargs.get('scanner_oidc_authz'))
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
        self.intel_google_safe_browsing = kwargs.get('intel_google_safe_browsing')
        self.intel_honey_score = kwargs.get('intel_honey_score')
        self.intel_threat_score = kwargs.get('intel_threat_score')
        self.intel_threat_type = kwargs.get('intel_threat_type')
        self.intel_hibp_exposure = bool(kwargs.get('intel_hibp_exposure'))
        self.intel_malc0de = bool(kwargs.get('intel_malc0de'))
        self.intel_crtsh = bool(kwargs.get('intel_crtsh'))
        self.intel_c2_callbackdomains = bool(kwargs.get('intel_c2_callbackdomains'))
        self.intel_sorbs = bool(kwargs.get('intel_sorbs'))
        self.intel_tor_exit_nodes = bool(kwargs.get('intel_tor_exit_nodes'))
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
        self.server_cipher_order = kwargs.get('server_cipher_order')
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

    def __setattr__(self, name, value):
        if name in [
            'dns_registered',
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
            'scanner_oidc_authz',
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
            'revocation_ocsp_url',
            'revocation_ocsp_crl',
            'revocation_ocsp_revoked',
            'revocation_ocsp_stapling',
            'revocation_ocsp_must_staple']:
            value = bool(value)
        super().__setattr__(name, value)

class DomainDocs(Elasticsearch_Collection_Adapter):
    def __init__(self):
        super().__init__('DomainDoc', __index__, 'domain_name')

class Domain(MySQL_Row_Adapter):
    _http_metadata = None
    stats = []
    orphans = []

    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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
        if name in ['screenshot', 'enabled', 'deleted']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_stats(self, latest_only=True):
        self.stats = []
        if latest_only:
            stmt = "SELECT domain_stats_id FROM domain_stats WHERE domain_id = %(domain_id)s AND (created_at = (SELECT domain_value FROM domain_stats WHERE domain_stat = 'http_last_checked' AND domain_id = %(domain_id)s ORDER BY domain_value DESC LIMIT 1) OR domain_stat = 'http_last_checked')"
        else:
            stmt = "SELECT domain_stats_id FROM domain_stats WHERE domain_id = %(domain_id)s ORDER BY created_at DESC"
        http_last_checked = None
        with replica_adapter as sql:
            results = sql.query(stmt, {'domain_id': self.domain_id}, cache_key=f'domain_stats/domain_id/{self.domain_id}')
            for val in results:
                domain_stat = DomainStat(domain_stats_id=val['domain_stats_id'])
                if domain_stat.hydrate():
                    self.stats.append(domain_stat)
                    if domain_stat.domain_stat == DomainStat.HTTP_LAST_CHECKED:
                        http_last_checked = domain_stat.domain_value
                        super().__setattr__(DomainStat.HTTP_LAST_CHECKED, http_last_checked)

        if http_last_checked:
            for domain_stat in self.stats:
                if domain_stat.created_at == http_last_checked:
                    super().__setattr__(domain_stat.domain_stat, domain_stat)

        return self

    def get_orphan_subdomains(self):
        self.orphans = []
        stmt = f"""
            SELECT domain_id FROM domains
            WHERE name LIKE '%{self.name}'
            AND account_id = %(account_id)s
            AND parent_domain_id != %(domain_id)s
            ORDER BY created_at DESC
        """
        with replica_adapter as sql:
            results = sql.query(stmt, {
                'account_id': self.account_id,
                'domain_id': self.domain_id,
            }, cache_key=False)
            for val in results:
                orphan = Domain(domain_id=val['domain_id'])
                if orphan.hydrate():
                    self.orphans.append(orphan)

        return self

    def fetch_metadata(self):
        if not self.account_id or not self.domain_id or not self.name:
            logger.warning('called Domain.fetch_metadata before initialising data')
            return self

        self._http_metadata = Metadata(f'https://{self.name}')
        try:
            self._http_metadata.head()
        except Exception as ex:
            logger.error(ex)

        if not str(self._http_metadata.code).startswith('2'):
            try:
                self._http_metadata.url = f'http://{self.name}'
                self._http_metadata.head()
            except Exception as ex:
                logger.error(ex)

        try:
            self._http_metadata.verification_check()
        except Exception as ex:
            logger.error(ex)
        try:
            self._http_metadata.safe_browsing_check()
        except Exception as ex:
            logger.error(ex)
        try:
            self._http_metadata.phishtank_check()
        except Exception as ex:
            logger.error(ex)
        try:
            self._http_metadata.projecthoneypot()
        except Exception as ex:
            logger.error(ex)
        try:
            self._http_metadata.honeyscore_check()
        except Exception as ex:
            logger.error(ex)
        return self

    def gather_stats(self):
        domain_stats = []
        now = datetime.utcnow().replace(microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
        if self._http_metadata.signature_algorithm:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_SIGNATURE_ALGORITHM,
                domain_value=self._http_metadata.signature_algorithm,
                created_at=now
            ))
        if self._http_metadata.negotiated_cipher:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_NEGOTIATED_CIPHER,
                domain_value=self._http_metadata.negotiated_cipher,
                created_at=now
            ))
        if self._http_metadata.code:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_CODE,
                domain_value=self._http_metadata.code,
                domain_data=self._http_metadata.reason,
                created_at=now
            ))
        if self._http_metadata.elapsed_duration:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_ELAPSED_DURATION,
                domain_value=self._http_metadata.elapsed_duration,
                created_at=now
            ))
        if self._http_metadata.protocol_version:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_PROTOCOL,
                domain_value=self._http_metadata.protocol_version,
                created_at=now
            ))
        if self._http_metadata.cookies:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_COOKIES,
                domain_data=json.dumps(self._http_metadata.cookies, default=str),
                created_at=now
            ))
        if self._http_metadata.headers:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTTP_HEADERS,
                domain_data=json.dumps(self._http_metadata.headers, default=str),
                created_at=now
            ))
            for header_name, header_value in self._http_metadata.headers.items():
                if header_name == 'x-powered-by':
                    domain_stats.append(DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.APPLICATION_BANNER,
                        domain_value=header_value,
                        created_at=now
                    ))
                if header_name == 'server':
                    domain_stats.append(DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.SERVER_BANNER,
                        domain_value=header_value,
                        created_at=now
                    ))
                if header_name == 'via':
                    domain_stats.append(DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.APPLICATION_PROXY,
                        domain_value=header_value,
                        created_at=now
                    ))

        if self._http_metadata.server_certificate:
            if self._http_metadata.sha1_fingerprint:
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SHA1_FINGERPRINT,
                    domain_value=self._http_metadata.sha1_fingerprint,
                    created_at=now
                ))
            if self._http_metadata.server_key_size:
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SERVER_KEY_SIZE,
                    domain_value=self._http_metadata.server_key_size,
                    created_at=now
                ))
            if self._http_metadata.pubkey_type:
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_SERVER_KEY_TYPE,
                    domain_value=self._http_metadata.pubkey_type,
                    created_at=now
                ))

            if self._http_metadata._json_certificate == '{}': # pylint: disable=protected-access
                self._http_metadata._json_certificate = '' # pylint: disable=protected-access
                try:
                    ctx0 = _create_unverified_context(check_hostname=False, purpose=Purpose.CLIENT_AUTH) # nosemgrep NOSONAR get the cert regardless of validation
                    with ctx0.wrap_socket(socket.socket(), server_hostname=self.name) as sock:
                        sock.connect((self.name, 443))
                        cert = sock.getpeercert()
                        self._http_metadata._json_certificate = json.dumps(cert, default=str) # pylint: disable=protected-access
                except SSLCertVerificationError as err:
                    logger.warning(err)

            try:
                ctx1 = create_default_context(purpose=Purpose.CLIENT_AUTH)
                with ctx1.wrap_socket(socket.socket(), server_hostname=self.name) as sock:
                    sock.connect((self.name, 443))

            except SSLCertVerificationError as err:
                if 'self signed certificate' in err.verify_message:
                    domain_stats.append(DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.HTTP_CERTIFICATE_IS_SELF_SIGNED,
                        domain_value=1,
                        domain_data=str(err),
                        created_at=now
                    ))
                else:
                    domain_stats.append(DomainStat(
                        domain_id=self.domain_id,
                        domain_stat=DomainStat.HTTP_CERTIFICATE_ERROR,
                        domain_value=err.verify_message,
                        domain_data=str(err),
                        created_at=now
                    ))

            if isinstance(self._http_metadata.server_certificate, X509):
                serial_number = self._http_metadata.server_certificate.get_serial_number()
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE,
                    domain_value=serial_number,
                    domain_data=self._http_metadata._json_certificate, # pylint: disable=protected-access
                    created_at=now
                ))

                issuer: X509Name = self._http_metadata.server_certificate.get_issuer()
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUER,
                    domain_value=issuer.commonName,
                    domain_data=self._http_metadata._json_certificate, # pylint: disable=protected-access
                    created_at=now
                ))
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUER_COUNTRY,
                    domain_value=issuer.countryName,
                    domain_data=self._http_metadata._json_certificate, # pylint: disable=protected-access
                    created_at=now
                ))
                not_before = datetime.strptime(self._http_metadata.server_certificate.get_notBefore().decode('ascii'), Metadata.X509_DATE_FMT)
                logger.info(f'notBefore {self._http_metadata.server_certificate.get_notBefore()} {not_before}')
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_ISSUED,
                    domain_value=not_before.isoformat(),
                    domain_data=f'{(datetime.utcnow() - not_before).days} days ago',
                    created_at=now
                ))

                not_after = datetime.strptime(self._http_metadata.server_certificate.get_notAfter().decode('ascii'), Metadata.X509_DATE_FMT)
                logger.info(f'notAfter {self._http_metadata.server_certificate.get_notAfter()} {not_after}')
                domain_stats.append(DomainStat(
                    domain_id=self.domain_id,
                    domain_stat=DomainStat.HTTP_CERTIFICATE_EXPIRY,
                    domain_value=not_after.isoformat(),
                    domain_data=f'Expired {(datetime.utcnow() - not_after).days} days ago' if not_after < datetime.utcnow() else f'Valid for {(not_after - datetime.utcnow()).days} days',
                    created_at=now
                ))

        account = Account(account_id=self.account_id)
        account.hydrate()
        domain_stats.append(DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.DNS_REGISTERED,
            domain_value=1 if self._http_metadata.registered else 0,
            created_at=now
        ))
        verified = bool(account.verification_hash == self._http_metadata.verification_hash)
        domain_stats.append(DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.APP_VERIFIED,
            domain_value=1 if verified else 0,
            created_at=now
        ))
        if not self._http_metadata.registered:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.DNS_ANSWER,
                domain_value=self._http_metadata.dns_answer,
                created_at=now
            ))

        if self._http_metadata.honey_score:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HONEY_SCORE,
                domain_value=self._http_metadata.honey_score,
                created_at=now
            ))

        if self._http_metadata.threat_score:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.THREAT_SCORE,
                domain_value=self._http_metadata.threat_score,
                created_at=now
            ))

        if self._http_metadata.threat_type:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.THREAT_TYPE,
                domain_value=self._http_metadata.threat_type,
                created_at=now
            ))

        phishtank_value = 'Unclassified'
        if self._http_metadata.phishtank:
            if self._http_metadata.phishtank.get('in_database'):
                phishtank_value = 'Reported Phish'
            elif self._http_metadata.phishtank.get('verified'):
                phishtank_value = 'Verified Phish'
        domain_stats.append(DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.PHISHTANK,
            domain_value=phishtank_value,
            domain_data=self._http_metadata.phishtank,
            created_at=now
        ))

        sb_value = 'Safe'
        if self._http_metadata.safe_browsing:
            sb_value = f'{self._http_metadata.safe_browsing.get("platform_type")} {self._http_metadata.safe_browsing.get("threat_type")}'.lower()
        domain_stats.append(DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.SAFE_BROWSING,
            domain_value=sb_value,
            domain_data=self._http_metadata.safe_browsing,
            created_at=now
        ))

        html_content = None
        try:
            html_content = self._http_metadata.get_site_content()
        except Exception as ex:
            logger.error(ex)
        if html_content:
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTML_SIZE,
                domain_value=len(html_content),
                created_at=now
            ))
        if self._http_metadata.get_site_title():
            domain_stats.append(DomainStat(
                domain_id=self.domain_id,
                domain_stat=DomainStat.HTML_TITLE,
                domain_value=self._http_metadata.get_site_title(),
                created_at=now
            ))

        domain_stat = DomainStat(
            domain_id=self.domain_id,
            domain_stat=DomainStat.HTTP_LAST_CHECKED,
        )
        domain_stat.hydrate(['domain_id', 'domain_stat'])
        domain_stat.domain_value = now
        domain_stat.persist(invalidations=[
            f'domain_stats/domain_id/{self.domain_id}'
        ])

        return domain_stats

class Domains(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Domain', __table__, __pk__)
