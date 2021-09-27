from tldextract import TLDExtract
from gunicorn.glogging import logging
from trivialsec.models.project import Project
from trivialsec.models.domain import Domain
from trivialsec.models.member import Member
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.service_type import ServiceType
from trivialsec.helpers.transport import Metadata
from trivialsec.services.jobs import SCAN_NEXT, queue_job


__module__ = 'trivialsec.services.domains'
logger = logging.getLogger(__name__)

def upsert_domain(domain :Domain, member :Member, project :Project, external_domain :bool = False) -> bool:
    saved = False
    scan_next_key = 'domain'
    extractor = TLDExtract(cache_dir='/tmp')
    ext = extractor(f'http://{domain.domain_name}')
    domain.apex = ext.registered_domain
    domain.tld = ext.suffix
    if domain.domain_name.endswith(f'.{domain.apex}'):
        scan_next_key = 'subdomain'
    query_string = f'domain_name:"{domain.domain_name}"'
    action = ActivityLog.ACTION_ADDED_DOMAIN
    check_domain = Domain()
    try:
        if check_domain.exists(query_string=query_string):
            action = ActivityLog.ACTION_UPDATE_DOMAIN
            domain.set_id(check_domain.get_id())
        saved = domain.persist()
        if saved:
            ActivityLog(member_id=member.member_id, action=action, description=domain.domain_name).persist(exists=False)
    except Exception as ex:
        logger.exception(ex)

    if external_domain is True:
        scan_next_key = 'external-domain'
    for service_type_name in SCAN_NEXT.get(scan_next_key, []):
        service_type = ServiceType(name=service_type_name)
        service_type.hydrate('name')
        queue_job(
            service_type=service_type,
            priority=2,
            member=member,
            project=project,
            params={'target': domain.domain_name, 'target_type': 'domain'},
            on_demand=False
        )

    return saved
