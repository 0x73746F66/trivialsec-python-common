from trivialsec.helpers import check_domain_rules
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.project import Project
from trivialsec.models.domain import Domain
from trivialsec.models.member import Member


__module__ = 'trivialsec.services.domains'

def handle_add_domain(domain_name: str, project: Project, current_user: Member) -> Domain:
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

    return domain
