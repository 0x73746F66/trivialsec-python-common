import json
import socket
from ssl import create_default_context, _create_unverified_context, SSLCertVerificationError, Purpose
from datetime import datetime
from OpenSSL.crypto import X509, X509Name
from gunicorn.glogging import logging
from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter, replica_adapter
from trivialsec.helpers.transport import Metadata
from .account import Account
from .domain_stat import DomainStat


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.models.domain'
__table__ = 'domains'
__pk__ = 'domain_id'

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
                        setattr(self, DomainStat.HTTP_LAST_CHECKED, http_last_checked)
        if http_last_checked:
            for domain_stat in self.stats:
                if domain_stat.created_at == http_last_checked:
                    setattr(self, domain_stat.domain_stat, domain_stat)

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
        now = datetime.utcnow().replace(microsecond=0).isoformat()
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
