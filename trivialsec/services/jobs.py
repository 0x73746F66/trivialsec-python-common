import json
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.job_run import JobRun
from trivialsec.models.service_type import ServiceType
from trivialsec.models.project import Project
from trivialsec.models.member import Member


__module__ = 'trivialsec.services.jobs'

class QueueData:
    def __init__(self, **kwargs):
        self.job_run_id = kwargs.get('job_run_id')
        self.queue_name = kwargs.get('queue_name')
        self.scan_type = kwargs.get('scan_type')
        self.is_passive = kwargs.get('scan_type') == 'passive'
        self.is_active = kwargs.get('scan_type') == 'active'
        self.worker_id = kwargs.get('worker_id')
        self.service_node_id = kwargs.get('service_node_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.service_type_name = kwargs.get('service_type_name')
        self.service_type_category = kwargs.get('service_type_category')
        self.job_uuid = kwargs.get('job_uuid')
        # amass, drill
        self.target = kwargs.get('target')
        # timings
        self.started_at = kwargs.get('started_at')
        self.completed_at = kwargs.get('completed_at')
        self.report_summary = kwargs.get('report_summary')

    def __str__(self):
        return json.dumps(self.__dict__, sort_keys=True, default=str)

    def __repr__(self):
        return str(self)

    def __iter__(self):
        yield from {
            'job_run_id': self.job_run_id,
            'target': self.target,
            'queue_name': self.queue_name,
            'service_type': {
                'type_id': self.service_type_id,
                'name': self.service_type_name,
                'category': self.service_type_category
            }
        }.items()

def queue_job(params: dict, service_type: ServiceType, member: Member, project=Project, priority: int = 0) -> JobRun:
    queue_data = QueueData(
        scan_type=params.get('scan_type', 'passive'),
        service_type_id=service_type.service_type_id,
        service_type_name=service_type.name,
        service_type_category=service_type.category,
        target=params.get('target')
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

    ActivityLog(
        member_id=member.member_id,
        action=ActivityLog.ACTION_ON_DEMAND_SCAN,
        description=f'{queue_data.scan_type} {service_type.category} {queue_data.target}'
    ).persist()
