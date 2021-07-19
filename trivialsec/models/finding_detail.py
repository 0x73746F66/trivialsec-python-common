from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.finding_detail'
__table__ = 'finding_details'
__pk__ = 'finding_detail_id'

class FindingDetail(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.finding_detail_id = kwargs.get('finding_detail_id')
        self.title = kwargs.get('title')
        self.description = kwargs.get('description')
        self.type_namespace = kwargs.get('type_namespace')
        self.type_category = kwargs.get('type_category')
        self.type_classifier = kwargs.get('type_classifier')
        self.confidence = kwargs.get('confidence', 0)
        self.severity_product = kwargs.get('severity_product', 0)
        self.recommendation = kwargs.get('recommendation')
        self.recommendation_url = kwargs.get('recommendation_url')
        self.cvss_vector = kwargs.get('cvss_vector')
        self.created_at = kwargs.get('created_at')
        self.review = kwargs.get('review')
        self.updated_at = kwargs.get('updated_at')
        self.modified_by_id = kwargs.get('modified_by_id')

class FindingDetails(DatabaseIterators):
    def __init__(self):
        super().__init__('FindingDetail', __table__, __pk__)
