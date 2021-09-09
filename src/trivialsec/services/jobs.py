import logging
import json
from datetime import datetime
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.job_run import JobRun, JobRuns
from trivialsec.models.service_type import ServiceType
from trivialsec.models.account import Account
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.project import Project
from trivialsec.models.domain import Domain
from trivialsec.models.member import Member
from trivialsec.helpers.config import config


__module__ = 'trivialsec.services.jobs'
SCAN_NEXT = {
    'domain': ['amass', 'metadata', 'drill', 'nmap', 'orphaned-files'],
    'subdomain': ['orphaned-files', 'subdomain-takeover'],
    'external-domain': ['metadata', 'saas-takeover', 'subdomain-takeover', 'dns-fronting', 'cname-collusion'],
    'tls-port': ['testssl', 'starttls-bugs', 'pwnedkeys'],
    'http-port': ['http-desync', 'request-smuggler'],
    'ldap-port': ['ldap'],
    'vpn-port': ['vpn-detect'],
    'kerberos-port': ['kerberoaster'],
    'html-port': ['screenshot', 'link-crawler', 'joomla', 'wordpress', 'compression-bugs', 'anti-bruteforce', 'xss-tester'],
    'json': [],
    'xml': ['saml-injection'],
    'open-port': ['owasp-zap', 'nikto2', 'file-protocols', 'popped-shells', 'reflected-ddos', 'dce-rpc'],
    'uri-path': ['owasp-zap', 'nikto2', 'git', 'dsstore', 'oauth2-checker'],
    'ipv4': [],
    'ipv6': [],
    'javascript': ['semgrep-javascript', 'npm-audit', 'eslint-plugin-security', 'nodejsscan', 'semgrep-react'],
    'golang': ['semgrep-golang', 'gosec'],
    'python': ['bandit', 'ossaudit', 'flask-xss'],
    'ruby': ['semgrep-ruby', 'minusworld-ruby-on-rails-xss'],
    'sourcecode': ['dependency-check', 'semgrep-r2c-ci', 'command-injection', 'insecure-transport', 'jwt', 'secrets', 'security-audit', 'docker-compose', 'dockerfile', 'findsecbugs', 'secret-strings', 'xss-tester'],
}
logger = logging.getLogger(__name__)

class QueueData:
    def __init__(self, **kwargs):
        self.job_uuid = kwargs.get('job_uuid')
        self.queued_by_member_id = kwargs.get('queued_by_member_id')
        self.on_demand = bool(kwargs.get('on_demand'))
        self.scan_type = kwargs.get('scan_type')
        self.is_passive = kwargs.get('scan_type') == 'passive'
        self.is_active = kwargs.get('scan_type') == 'active'
        self.worker_id = kwargs.get('worker_id')
        self.service_node_id = kwargs.get('service_node_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.service_type_name = kwargs.get('service_type_name')
        self.service_type_category = kwargs.get('service_type_category')
        self.target = kwargs.get('target')
        self.target_type = kwargs.get('target_type')
        self.report_summary = kwargs.get('report_summary')
        self.started_at = kwargs.get('started_at')
        self.completed_at = kwargs.get('completed_at')

    def __str__(self):
        return json.dumps(self.__dict__, sort_keys=True, default=str)

    def __repr__(self):
        return str(self)

    def __iter__(self):
        yield from {
            'job_uuid': self.job_uuid,
            'queued_by_member_id': self.queued_by_member_id,
            'on_demand': self.on_demand,
            'scan_type': self.scan_type,
            'is_passive': self.is_passive,
            'is_active': self.is_active,
            'service_type': {
                'node_id': self.service_node_id,
                'type_id': self.service_type_id,
                'name': self.service_type_name,
                'category': self.service_type_category
            },
            self.target_type: self.target,
            'timings': {
                'started_at': self.started_at,
                'completed_at': self.completed_at,
            },
            'report_summary': self.report_summary
        }.items()

def queue_job(params :dict, service_type: ServiceType, member: Member, project=Project, priority: int = 0, on_demand :bool = True) -> JobRun:
    queue_data = QueueData(
        queued_by_member_id=member.member_id,
        on_demand=on_demand,
        scan_type=params.get('scan_type', 'passive'),
        service_type_id=service_type.service_type_id,
        service_type_name=service_type.name,
        service_type_category=service_type.category,
        target=params.get('target'),
        target_type=params.get('target_type'),
    )
    new_job_run = JobRun(
        account_id=member.account_id,
        project_id=project.project_id,
        service_type_id=service_type.service_type_id,
        queue_data=str(queue_data),
        state=ServiceType.STATE_QUEUED,
        priority=priority
    )
    if not new_job_run.persist():
        raise ValueError(f'queue_job {queue_data.target} persist error')

    action=ActivityLog.ACTION_ON_DEMAND_PASSIVE_SCAN if queue_data.scan_type == 'passive' else ActivityLog.ACTION_ON_DEMAND_ACTIVE_SCAN
    if on_demand is False:
        action=ActivityLog.ACTION_AUTO_PASSIVE_SCAN if queue_data.scan_type == 'passive' else ActivityLog.ACTION_AUTO_ACTIVE_SCAN

    ActivityLog(
        member_id=member.member_id,
        action=action,
        description=f'{queue_data.scan_type} {service_type.category} {queue_data.target}'
    ).persist()

def get_next_job(service_type_id :int = None, service_type_name :str = None, account_id :int = None):
    current_service_type = ServiceType()
    if service_type_id is not None:
        current_service_type.service_type_id = service_type_id
        current_service_type.hydrate('name')
    if service_type_name is not None:
        current_service_type.name = service_type_name
        current_service_type.hydrate('name')
    logger.info(f'checking {current_service_type.name} queue for service {config.node_id}')
    job_params = [
        ('state', ServiceType.STATE_QUEUED),
        ('service_type_id', current_service_type.service_type_id)
    ]
    if account_id is not None:
        job_params.append(('account_id', account_id))

    jobs: JobRuns = JobRuns().find_by(
        job_params,
        order_by=['priority', 'DESC'],
        limit=1,
    )
    if len(jobs) != 1 or not isinstance(jobs[0], JobRun):
        logger.info(f'{current_service_type.name} queue is empty')
        return None

    current_job: JobRun = jobs[0]
    setattr(current_job, 'service_type', current_service_type)
    current_job.node_id = config.node_id
    current_job.started_at = datetime.utcnow().replace(microsecond=0).isoformat()
    current_job.updated_at = current_job.started_at
    data = json.loads(current_job.queue_data)
    data['service_node_id'] = config.node_id
    data['started_at'] = current_job.started_at
    current_job.queue_data = QueueData(**data)

    account = Account(account_id=current_job.account_id)
    if not account.hydrate():
        logger.error(f'Error loading account {current_job.account_id}')
        return None
    account_config = AccountConfig(account_id=current_job.account_id)
    if not account_config.hydrate():
        logger.error(f'Error loading account config {current_job.account_id}')
        return None
    setattr(account, 'config', account_config)
    setattr(current_job, 'account', account)
    member = Member(member_id=current_job.queue_data.queued_by_member_id)
    if not member.hydrate():
        logger.error(f'Error loading member {current_job.queue_data.queued_by_member_id}')
        return None
    setattr(current_job, 'member', member)
    project = Project(project_id=current_job.project_id)
    if not project.hydrate():
        logger.error(f'Error loading project {current_job.project_id}')
        return None
    setattr(current_job, 'project', project)
    if current_job.queue_data.target_type == 'domain':
        domain = Domain(domian_name=current_job.queue_data.target)
        if not domain.hydrate(query_string=f'domain_name:"{current_job.queue_data.target}"'):
            logger.error(f'Error loading domain {current_job.queue_data.target}')
            return None
        setattr(current_job, 'domain', domain)

    return current_job
