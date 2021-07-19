import re
from datetime import datetime
from gunicorn.glogging import logging
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.member import Member
from trivialsec.models.finding import Finding
from trivialsec.models.finding_note import FindingNote


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.services.findings'

def score_to_rating(score: int) -> str:
    if score == 0:
        return 'INFO'
    if score >= 1 and score < 40:
        return 'LOW'
    if score >= 40 and score < 70:
        return 'MEDIUM'
    if score >= 70 and score < 90:
        return 'HIGH'
    if score >= 90 and score <= 100:
        return 'CRITICAL'

    return 'NOT SCORED'

def rating_to_score(rating: str) -> int:
    if rating == 'INFO':
        return 0
    if rating == 'LOW':
        return 35
    if rating == 'MEDIUM':
        return 65
    if rating == 'HIGH':
        return 85
    if rating == 'CRITICAL':
        return 95

    return -1

def score_to_confidence(score: int) -> str:
    if score >= 0 and score < 45:
        return 'LOW'
    if score >= 45 and score < 85:
        return 'MEDIUM'
    if score >= 85 and score <= 100:
        return 'HIGH'

    return 'NOT SCORED'

def aggregate_sum(findings: list, rating: str, using: str, scoring_func: str) -> int:
    return sum(1 for i in findings if globals()[scoring_func](getattr(i, using)) == rating)

def extract_cve_id(search_string: str) -> str:
    cve = None
    try:
        matches = re.search(r'CVE-\d{4}-\d{4,7}', search_string)
        if matches:
            cve = matches.group()
    except Exception as ex:
        logger.error(ex)
    return cve

def extract_cwe_id(search_string: str) -> str:
    cwe = None
    try:
        matches = re.search(r'CWE-\d{2,3}', search_string)
        if matches:
            cwe = matches.group()
    except Exception as ex:
        logger.error(ex)
    return cwe

def handle_finding_actions(params: dict, member: Member) -> Finding:
    action = params.get('action')
    finding_id = params.get('finding_id')
    if action == 'archive':
        finding = Finding(finding_id=finding_id)
        finding.hydrate()
        finding.archived = True
        finding.updated_at = datetime.utcnow()
        if finding.persist():
            ActivityLog(member_id=member.member_id, action='archived_finding', description=finding.finding_id).persist()
            return finding

    if action == 'assign':
        assignee_id = params.get('assignee_id')
        if assignee_id:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.assignee_id = assignee_id
            finding.workflow_state = finding.WORKFLOW_ASSIGNED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='assigned_finding', description=assignee_id).persist()
            return finding

    if action == 'project':
        project_id = params.get('project_id')
        if project_id:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.project_id = project_id
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='finding_project_changed', description=project_id).persist()
            return finding

    if action == 'verify':
        verification_state = params.get('verification_state').upper()
        if verification_state:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.verification_state = verification_state
            if verification_state in [finding.VERIFY_BENIGN_POSITIVE, finding.VERIFY_FALSE_POSITIVE]:
                finding.workflow_state = finding.WORKFLOW_RESOLVED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='verify_finding', description=verification_state).persist()
            return finding

    if action == 'severity':
        severity = params.get('severity')
        if severity:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.severity_normalized = rating_to_score(severity)
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='severity_finding', description=severity).persist()
            return finding

    if action == 'defer':
        defer = params.get('defer')
        if defer:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.defer_to = defer
            finding.updated_at = datetime.utcnow()
            finding.workflow_state = finding.WORKFLOW_DEFERRED
            finding.persist()
            ActivityLog(member_id=member.member_id, action='defer_finding', description=defer).persist()
            return finding

    if action == 'workflow':
        workflow_state = params.get('workflow_state').upper()
        if workflow_state:
            finding = Finding(finding_id=finding_id)
            finding.hydrate()
            finding.workflow_state = workflow_state
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='finding_workflow', description=workflow_state).persist()
            return finding

    if action == 'unassign':
        finding = Finding(finding_id=finding_id)
        finding.hydrate()
        old_assignee_id = finding.assignee_id
        finding.assignee_id = None
        finding.workflow_state = finding.WORKFLOW_NEW
        finding.updated_at = datetime.utcnow()
        finding.persist()
        ActivityLog(member_id=member.member_id, action='unassigned_finding', description=old_assignee_id).persist()
        return finding

    if action == 'resolve':
        text = params.get('reason')
        finding = Finding(finding_id=finding_id)
        finding.hydrate()
        note = FindingNote(
            finding_id=finding_id,
            account_id=member.account_id,
            member_id=member.member_id,
            text=text,
        )
        if note.persist():
            finding.assignee_id = member.member_id
            finding.workflow_state = finding.WORKFLOW_RESOLVED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='resolved_finding', description=note.finding_note_id).persist()
            return finding

    if action == 'note':
        text = params.get('text')
        finding = Finding(finding_id=finding_id)
        finding.hydrate()
        note = FindingNote(
            finding_id=finding_id,
            account_id=member.account_id,
            member_id=member.member_id,
            text=text,
        )
        if note.persist():
            finding.assignee_id = member.member_id
            finding.workflow_state = finding.WORKFLOW_IN_PROGRESS
            finding.updated_at = datetime.utcnow()
            finding.persist()
            ActivityLog(member_id=member.member_id, action='noted_finding', description=note.finding_note_id).persist()
            return finding

    return None
