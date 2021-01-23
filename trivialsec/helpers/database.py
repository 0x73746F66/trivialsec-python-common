import time
import json
import redis
import mysql.connector
from datetime import timedelta
from retry.api import retry
from .config import config
from .log_manager import logger


__module__ = 'trivialsec.helpers.database'

class MySQLDatabase:
    con = None
    cur = None
    retry_count = 0
    user = None
    password = None
    host = None
    database = None
    pool_size = None
    raise_on_warnings = True
    redis = redis.Redis(host=config.redis.get('host'), ssl=bool(config.redis.get('ssl')))

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, mtype, value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def __init__(self, **kwargs):
        self.user = kwargs.get('user')
        self.password = kwargs.get('password')
        self.host = kwargs.get('host')
        self.database = kwargs.get('database')
        self.raise_on_warnings = kwargs.get('raise_on_warnings', True)
        cache_ttl = kwargs.get('cache_ttl')
        if cache_ttl:
            self.cache_ttl = cache_ttl
        pool_size = kwargs.get('pool_size')
        if pool_size:
            self.pool_size = pool_size

    def close(self):
        try:
            if self.cur is not None:
                self.cur = None
            if self.con is not None:
                self.con.close()
        except Exception:
            pass

    @retry(Exception, tries=3, delay=.5, backoff=1.5)
    def connect(self):
        params = {
            'user': self.user,
            'password': self.password,
            'host': self.host,
            'database': self.database,
        }
        if self.pool_size:
            params['pool_size'] = self.pool_size
        if self.raise_on_warnings:
            params['raise_on_warnings'] = self.raise_on_warnings

        if not self.con or not self.con.is_connected():
            try:
                self.con = mysql.connector.connect(**params)
            except mysql.connector.Error as err:
                if err.errno == 1040: # ER_CON_COUNT_ERROR
                    self.retry_count += 1
                    if self.retry_count >= 10:
                        raise err
                    time.sleep(1)
                    return self.connect()
                raise err

        return self

    def invalidate_cache(self, invalidations: list):
        for invalidation_key in invalidations:
            self.redis.delete(f'{config.app_version}{invalidation_key}')

    def query_one(self, sql, params=None, cache_key: str = None, invalidations: list = None, cache_ttl: timedelta = timedelta(seconds=int(config.redis.get('ttl', 300)))):
        if cache_key:
            redis_value = self._get_from_redis(cache_key)
            if redis_value is not None:
                return redis_value

        self.cur = self.con.cursor(buffered=True)
        self.cur.execute(sql, params)
        data = {}
        row = self.cur.fetchone()
        logger.debug(self.cur.statement)
        logger.debug(row)
        self.cur.close()
        if row:
            index = 0
            for col in self.cur.column_names:
                data[col] = row[index]
                index += 1
        response = data if data else row
        if cache_key and response is not None:
            self._save_to_redis(cache_key, response, cache_ttl)
            response = self._get_from_redis(cache_key)
        if invalidations is not None:
            self.invalidate_cache(invalidations)

        return response

    def table_cols(self, table, cache_ttl: timedelta = timedelta(seconds=int(config.redis.get('ttl', 300)))):
        cache_key = f'{table}/columns'
        logger.debug(f'checking cache {cache_key}')
        redis_value = self._get_from_redis(cache_key)
        if redis_value is not None:
            logger.debug(f'found in cache {redis_value}')
            return redis_value
        sql = f'SELECT `column_name` FROM `information_schema`.`columns` WHERE `table_schema` = "{self.database}" AND `table_name` = %(table)s'
        logger.debug(sql)
        self.cur = self.con.cursor(buffered=True)
        self.cur.execute(sql, {'table': table})
        cols = set()
        for row in self.cur:
            cols.add(row[0])

        logger.debug(cols)
        self.cur.close()
        if len(cols) > 0:
            self._save_to_redis(cache_key, cols, cache_ttl)
            cols = self._get_from_redis(cache_key)

        return cols

    def query(self, sql, params=None, cache_key: str = None, invalidations: list = None, cache_ttl: timedelta = timedelta(seconds=int(config.redis.get('ttl', 300)))):
        if cache_key is not None:
            redis_value = self._get_from_redis(cache_key)
            if redis_value is not None:
                return redis_value

        results = []
        self.cur = self.con.cursor(buffered=True)
        self.cur.execute(sql, params)

        if sql.lower().startswith('select'):
            for row in self.cur:
                data = {}
                index = 0
                for col in self.cur.column_names:
                    data[col] = row[index]
                    index += 1
                results.append(data)
        elif sql.lower().startswith('insert'):
            results = self.cur.lastrowid
        elif sql.lower().startswith('update') or sql.lower().startswith('delete'):
            results = self.cur.rowcount

        logger.debug(self.cur.statement)
        logger.debug(results)
        self.cur.close()
        if cache_key and results is not None:
            self._save_to_redis(cache_key, results, cache_ttl)
            results = self._get_from_redis(cache_key)
        if invalidations is not None:
            self.invalidate_cache(invalidations)

        return results

    def _get_from_redis(self, cache_key: str):
        redis_value = None
        try:
            if isinstance(cache_key, str):
                redis_value = self.redis.get(f'{config.app_version}{cache_key}')
                logger.debug(f'{cache_key} {redis_value}')
        except Exception as ex:
            logger.exception(ex)
            return None

        if redis_value is not None:
            logger.debug(f'CACHE HIT {cache_key}')
            return json.loads(redis_value.decode())

        logger.debug(f'CACHE MISS {cache_key}')
        return None

    def _save_to_redis(self, cache_key: str, results, cache_ttl: timedelta = timedelta(seconds=int(config.redis.get('ttl', 300)))):
        redis_data = results
        if isinstance(results, set):
            redis_data = list(results)
        logger.debug(f'CACHE STORE {cache_key}')
        str_value = json.dumps(redis_data, default=str)
        return self.redis.set(f'{config.app_version}{cache_key}', str_value, ex=cache_ttl)

mysql_adapter = MySQLDatabase(**config.mysql)
