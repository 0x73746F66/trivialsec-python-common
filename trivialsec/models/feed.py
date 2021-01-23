from random import shuffle
from datetime import datetime, timedelta
from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators
from trivialsec.helpers.database import mysql_adapter


__module__ = 'trivialsec.models.feed'

class Feed(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('feeds', 'feed_id')
        self.feed_id = kwargs.get('feed_id')
        self.name = kwargs.get('name')
        self.category = kwargs.get('category')
        self.description = kwargs.get('description')
        self.url = kwargs.get('url')
        self.type = kwargs.get('type')
        self.method = kwargs.get('method')
        self.username = kwargs.get('username')
        self.credential_key = kwargs.get('credential_key')
        self.http_status = kwargs.get('http_status')
        self.http_code = kwargs.get('http_code')
        self.alert_title = kwargs.get('alert_title')
        self.schedule = kwargs.get('schedule')
        self.feed_site = kwargs.get('feed_site')
        self.abuse_email = kwargs.get('abuse_email')
        self.disabled = bool(kwargs.get('disabled'))
        self.start_check = kwargs.get('start_check')
        self.last_checked = kwargs.get('last_checked')

    def __setattr__(self, name, value):
        if name in ['disabled']:
            value = bool(value)
        super().__setattr__(name, value)

class Feeds(DatabaseIterators):
    def __init__(self):
        super().__init__('Feed')

    def num_running(self, category: str) -> int:
        with mysql_adapter as database:
            results = database.query_one("""SELECT count(*) as num FROM feeds WHERE
                category = %(category)s AND
                start_check IS NOT NULL AND
                last_checked IS NOT NULL AND
                start_check > last_checked
                """, {'category': category})
            return int(results['num'])

    def num_errored(self, category: str) -> int:
        with mysql_adapter as database:
            results = database.query_one("""SELECT count(*) as num FROM feeds WHERE
                category = %(category)s AND
                http_code = 200
                """, {'category': category})
            return int(results['num'])

    def num_queued(self, category: str) -> int:
        return len(self.get_queued(category, 1000))

    def get_queued(self, category: str, limit: int = 10) -> list:
        ret = []
        data = {
            'category': category,
            'hourly': datetime.utcnow() - timedelta(hours=1),
            'daily': datetime.utcnow() - timedelta(days=1),
            'monthly': datetime.utcnow() - timedelta(weeks=4),
        }
        with mysql_adapter as database:
            results = database.query(f"""SELECT * FROM feeds WHERE
                category = %(category)s AND
                start_check IS NULL OR
                last_checked IS NULL OR
                (schedule = 'hourly' AND last_checked < %(hourly)s) OR
                (schedule = 'daily' AND last_checked < %(daily)s) OR
                (schedule = 'monthly' AND last_checked < %(monthly)s)
                ORDER BY start_check ASC
                LIMIT {limit}""", data)

            shuffle(results)
            for result in results:
                feed = Feed()
                for col, val in result.items():
                    setattr(feed, col, val)
                ret.append(feed)

        return ret
