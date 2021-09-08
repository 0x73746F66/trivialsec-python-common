from datetime import datetime
from gunicorn.glogging import logging
from trivialsec.models.domain import Domain
from trivialsec.helpers.transport import Metadata, X509_DATE_FMT

__module__ = 'trivialsec.services.domains'
logger = logging.getLogger(__name__)

def upsert_domain(domain :Domain) -> bool:
    check_domain = Domain()
    if check_domain.exists(query_string=f'domain_name:"{domain.domain_name}"'):
        domain.set_id(check_domain.get_id())
    return domain.persist()

def fetch_metadata(domain_name :str, port :int = None):
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

    try:
        http_metadata.website_content()
    except Exception as ex:
        logger.error(ex)
