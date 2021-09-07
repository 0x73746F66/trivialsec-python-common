from datetime import datetime
from gunicorn.glogging import logging
from trivialsec.models.domain import Domain
from trivialsec.helpers.transport import Metadata, X509_DATE_FMT


__module__ = 'trivialsec.services.domains'
logger = logging.getLogger(__name__)

def fetch_metadata(domain_name :str, port :int = None):
    domain = Domain(domain_name=domain_name)
    if not domain.hydrate():
        return None

    if port is not None and isinstance(port, int):
        http_metadata = Metadata(f'http://{domain_name}:{port}')
    else:
        http_metadata = Metadata(f'http://{domain_name}')

    try:
        http_metadata.head()
    except Exception as ex:
        logger.error(ex)

    if not str(http_metadata.code).startswith('2'):
        try:
            if port is not None and isinstance(port, int):
                http_metadata = Metadata(f'https://{domain_name}:{port}')
            else:
                http_metadata = Metadata(f'https://{domain_name}')
        except Exception as ex:
            logger.error(ex)

    try:
        http_metadata.verification_check()
    except Exception as ex:
        logger.error(ex)
    try:
        http_metadata.safe_browsing_check()
    except Exception as ex:
        logger.error(ex)
    try:
        http_metadata.phishtank_check()
    except Exception as ex:
        logger.error(ex)
    try:
        http_metadata.projecthoneypot()
    except Exception as ex:
        logger.error(ex)
    try:
        http_metadata.honeyscore_check()
    except Exception as ex:
        logger.error(ex)


    now = datetime.utcnow().replace(microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
    if http_metadata.signature_algorithm:
        {'domain_stat': HTTP_SIGNATURE_ALGORITHM,
            'domain_value': http_metadata.signature_algorithm
        })
    if http_metadata.negotiated_cipher:
        {'domain_stat': HTTP_NEGOTIATED_CIPHER,
            'domain_value': http_metadata.negotiated_cipher
        })
    if http_metadata.code:
        {'domain_stat': HTTP_CODE,
            'domain_value': http_metadata.code,
            domain_data=http_metadata.reason
        })
    if http_metadata.elapsed_duration:
        {'domain_stat': HTTP_ELAPSED_DURATION,
            'domain_value': http_metadata.elapsed_duration
        })
    if http_metadata.protocol_version:
        {'domain_stat': HTTP_PROTOCOL,
            'domain_value': http_metadata.protocol_version
        })
    if http_metadata.cookies:
        {'domain_stat': HTTP_COOKIES,
            domain_data=json.dumps(http_metadata.cookies, default=str)
        })
    if http_metadata.headers:
        {'domain_stat': HTTP_HEADERS,
            domain_data=json.dumps(http_metadata.headers, default=str)
        })
        for header_name, header_value in http_metadata.headers.items():
            if header_name == 'x-powered-by':
                {
                    'domain_id': self.domain_id,
                    'domain_stat': APPLICATION_BANNER,
                    'domain_value': header_value,
                    created_at=now
                })
            if header_name == 'server':
                {
                    'domain_id': self.domain_id,
                    'domain_stat': SERVER_BANNER,
                    'domain_value': header_value,
                    created_at=now
                })
            if header_name == 'via':
                {
                    'domain_id': self.domain_id,
                    'domain_stat': APPLICATION_PROXY,
                    'domain_value': header_value,
                    created_at=now
                })

    if http_metadata.server_certificate:
        if http_metadata.sha1_fingerprint:
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_SHA1_FINGERPRINT,
                'domain_value': http_metadata.sha1_fingerprint,
                created_at=now
            })
        if http_metadata.server_key_size:
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_SERVER_KEY_SIZE,
                'domain_value': http_metadata.server_key_size,
                created_at=now
            })
        if http_metadata.pubkey_type:
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_SERVER_KEY_TYPE,
                'domain_value': http_metadata.pubkey_type,
                created_at=now
            })

        if http_metadata._json_certificate == '{}': # pylint: disable=protected-access
            http_metadata._json_certificate = '' # pylint: disable=protected-access
            try:
                ctx0 = _create_unverified_context(check_hostname=False, purpose=Purpose.CLIENT_AUTH) # nosemgrep NOSONAR get the cert regardless of validation
                with ctx0.wrap_socket(socket.socket(), server_hostname=self.name) as sock:
                    sock.connect((self.name, 443})
                    cert = sock.getpeercert()
                    http_metadata._json_certificate = json.dumps(cert, default=str) # pylint: disable=protected-access
            except SSLCertVerificationError as err:
                logger.warning(err)

        try:
            ctx1 = create_default_context(purpose=Purpose.CLIENT_AUTH)
            with ctx1.wrap_socket(socket.socket(), server_hostname=self.name) as sock:
                sock.connect((self.name, 443})

        except SSLCertVerificationError as err:
            if 'self signed certificate' in err.verify_message:
                {
                    'domain_id': self.domain_id,
                    'domain_stat': HTTP_CERTIFICATE_IS_SELF_SIGNED,
                    'domain_value': 1,
                    domain_data=str(err),
                    created_at=now
                })
            else:
                {
                    'domain_id': self.domain_id,
                    'domain_stat': HTTP_CERTIFICATE_ERROR,
                    'domain_value': err.verify_message,
                    domain_data=str(err),
                    created_at=now
                })

        if isinstance(http_metadata.server_certificate, X509):
            serial_number = http_metadata.server_certificate.get_serial_number()
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_CERTIFICATE,
                'domain_value': serial_number,
                domain_data=http_metadata._json_certificate, # pylint: disable=protected-access
                created_at=now
            })

            issuer: X509Name = http_metadata.server_certificate.get_issuer()
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_CERTIFICATE_ISSUER,
                'domain_value': issuer.commonName,
                domain_data=http_metadata._json_certificate, # pylint: disable=protected-access
                created_at=now
            })
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_CERTIFICATE_ISSUER_COUNTRY,
                'domain_value': issuer.countryName,
                domain_data=http_metadata._json_certificate, # pylint: disable=protected-access
                created_at=now
            })
            not_before = datetime.strptime(http_metadata.server_certificate.get_notBefore().decode('ascii'), X509_DATE_FMT)
            logger.info(f'notBefore {http_metadata.server_certificate.get_notBefore()} {not_before}')
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_CERTIFICATE_ISSUED,
                'domain_value': not_before.isoformat(),
                domain_data=f'{(datetime.utcnow() - not_before).days} days ago',
                created_at=now
            })

            not_after = datetime.strptime(http_metadata.server_certificate.get_notAfter().decode('ascii'), X509_DATE_FMT)
            logger.info(f'notAfter {http_metadata.server_certificate.get_notAfter()} {not_after}')
            {
                'domain_id': self.domain_id,
                'domain_stat': HTTP_CERTIFICATE_EXPIRY,
                'domain_value': not_after.isoformat(),
                domain_data=f'Expired {(datetime.utcnow() - not_after).days} days ago' if not_after < datetime.utcnow() else f'Valid for {(not_after - datetime.utcnow(}).days} days',
                created_at=now
            })

    account = Account(account_id=self.account_id)
    account.hydrate()
    {
        'domain_id': self.domain_id,
        'domain_stat': DNS_REGISTERED,
        'domain_value': 1 if http_metadata.registered else 0,
        created_at=now
    })
    verified = bool(account.verification_hash == http_metadata.verification_hash)
    {
        'domain_id': self.domain_id,
        'domain_stat': APP_VERIFIED,
        'domain_value': 1 if verified else 0,
        created_at=now
    })
    if not http_metadata.registered:
        {'domain_stat': DNS_ANSWER,
            'domain_value': http_metadata.dns_answer
        })

    if http_metadata.honey_score:
        {'domain_stat': HONEY_SCORE,
            'domain_value': http_metadata.honey_score
        })

    if http_metadata.threat_score:
        {'domain_stat': THREAT_SCORE,
            'domain_value': http_metadata.threat_score
        })

    if http_metadata.threat_type:
        {'domain_stat': THREAT_TYPE,
            'domain_value': http_metadata.threat_type
        })

    phishtank_value = 'Unclassified'
    if http_metadata.phishtank:
        if http_metadata.phishtank.get('in_database'):
            phishtank_value = 'Reported Phish'
        elif http_metadata.phishtank.get('verified'):
            phishtank_value = 'Verified Phish'
    {
        'domain_id': self.domain_id,
        'domain_stat': PHISHTANK,
        'domain_value': phishtank_value,
        domain_data=http_metadata.phishtank,
        created_at=now
    })

    sb_value = 'Safe'
    if http_metadata.safe_browsing:
        sb_value = f'{http_metadata.safe_browsing.get("platform_type")} {http_metadata.safe_browsing.get("threat_type")}'.lower()
    {
        'domain_id': self.domain_id,
        'domain_stat': SAFE_BROWSING,
        'domain_value': sb_value,
        domain_data=http_metadata.safe_browsing,
        created_at=now
    })

    html_content = None
    try:
        html_content = http_metadata.get_site_content()
    except Exception as ex:
        logger.error(ex)
    if html_content:
        {'domain_stat': HTML_SIZE,
            'domain_value': len(html_content)
        })
    if http_metadata.get_site_title():
        {'domain_stat': HTML_TITLE,
            'domain_value': http_metadata.get_site_title()
        })

    domain_stat = {
        'domain_id': self.domain_id,
        'domain_stat': HTTP_LAST_CHECKED,
    )
    domain_stat.hydrate(['domain_id', 'domain_stat'])
    domain_stat.domain_value = now
    domain_stat.persist(invalidations=[
        f'domain_stats/domain_id/{self.domain_id}'
    ])
