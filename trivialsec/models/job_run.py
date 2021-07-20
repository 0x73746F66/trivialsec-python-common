from random import choice
from string import ascii_lowercase
from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators
from trivialsec.helpers.database import mysql_adapter

__module__ = 'trivialsec.models.job_run'
__table__ = 'job_runs'
__pk__ = 'job_run_id'

class JobRun(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.job_run_id = kwargs.get('job_run_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.node_id = kwargs.get('node_id')
        self.worker_id = kwargs.get('worker_id')
        self.queue_data = kwargs.get('queue_data')
        self.target = kwargs.get('target')
        self.state = kwargs.get('state')
        self.worker_message = kwargs.get('worker_message')
        self.priority = kwargs.get('priority', 0)
        self.created_at = kwargs.get('created_at')
        self.started_at = kwargs.get('started_at')
        self.updated_at = kwargs.get('updated_at')
        self.completed_at = kwargs.get('completed_at')

class JobRuns(DatabaseIterators):
    def __init__(self):
        super().__init__('JobRun', __table__, __pk__)

    def query_json(self, search_filter :list, limit: int = 1, offset: int = 0, conditional = ' AND '):
        data = {}
        conditionals = []
        columns = JobRun().cols()
        for key, val in search_filter:
            if key in columns:
                if val is None:
                    conditionals.append(f' {key} is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditionals.append(f' {key} in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditionals.append(f' {key} = %({key})s ')
            else:
                placeholder = ''.join(choice(ascii_lowercase) for _ in range(8))
                data[placeholder] = val
                conditionals.append(f" JSON_EXTRACT(queue_data, '{key}') = %({placeholder})s ")
        where = conditional.join(conditionals)
        sql = f"SELECT * FROM job_runs WHERE {where} LIMIT {offset},{limit}"
        with mysql_adapter as database:
            results = database.query(sql, data)
            self._load_items(results)

        return self
