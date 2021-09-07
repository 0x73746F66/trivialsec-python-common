import tldextract
from aslookup import get_as_data
from aslookup.exceptions import NoASDataError, NonroutableAddressError, AddressFormatError
from gunicorn.glogging import logging
from trivialsec.helpers import check_domain_rules
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.project import Project
from trivialsec.models.domain import Domain, DomainDoc
from trivialsec.models.member import Member


__module__ = 'trivialsec.services.domains'
logger = logging.getLogger(__name__)

def handle_add_domain(domain_name :str, project: Project, current_user: Member) -> Domain:
    res = check_domain_rules(domain_name)
    if not res:
        return None

    domain = Domain(
        name=domain_name,
        account_id=current_user.account_id,
        project_id=project.project_id,
    )
    if domain.exists(['name', 'project_id', 'account_id']):
        domain.hydrate()
        domain.deleted = False
    domain.source = f'Project {project.name}'
    domain.enabled = False

    if domain.persist():
        ActivityLog(member_id=current_user.member_id, action='added_domain', description=domain_name).persist()

    ext = tldextract.extract(f'http://{domain_name}')
    doc = DomainDoc()
    doc.domain_name = domain_name
    doc.apex = ext.registered_domain
    doc.tld = ext.suffix
    doc.persist()

    return domain
