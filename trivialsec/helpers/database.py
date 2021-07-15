import importlib
import re
import time
import json
import mysql.connector
from datetime import datetime, timedelta
from retry.api import retry
from .config import config
from gunicorn.glogging import logging


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.database'

class MySQLDatabase:
    con = None
    cur = None
    retry_count = 0
    user = None
    host = None
    database = None
    pool_size = None
    raise_on_warnings = True

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, mtype, value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def __init__(self, **kwargs):
        self.user = kwargs.get('user')
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

    @retry(mysql.connector.Error, tries=3, delay=.5, backoff=1.5)
    def connect(self):
        params = {
            'user': self.user,
            'password': config.mysql_password,
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
                self.retry_count = 0
            except mysql.connector.Error as err:
                if err.errno == 1045: # Access denied for user
                    logger.warning(f'Access denied for user {params}')
                elif err.errno == 1040: # ER_CON_COUNT_ERROR
                    self.retry_count += 1
                    if self.retry_count >= 10:
                        raise err
                    time.sleep(1)
                    return self.connect()
                raise err

        return self

    def invalidate_cache(self, invalidations: list):
        for invalidation_key in invalidations:
            config._redis.delete(f'{config.app_version}{invalidation_key}')

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
                redis_value = config._redis.get(f'{config.app_version}{cache_key}')
                logger.debug(f'{cache_key} {redis_value}')
        except Exception as ex:
            logger.error(ex)
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
        return config._redis.set(f'{config.app_version}{cache_key}', str_value, ex=cache_ttl)

mysql_adapter = MySQLDatabase(**config.mysql)

class DatabaseIterators:
    def __init__(self, class_name):
        self.__table = f"{re.sub(r'(?<!^)(?=[A-Z])', '_', class_name).lower()}s"
        self.__class_name = class_name
        self.__index = 0
        self.__items = []

    def _load_items(self, results: list):
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        for result in results:
            model = class_()
            for col, val in result.items():
                setattr(model, col, val)
            self.__items.append(model)
        self.__index = 0

    def find_by(self, search_filter: list, conditional: str = 'AND', order_by: list = None, limit: int = 1000, offset: int = 0, cache_key: str = None, ttl_seconds: int = 30):
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        sql = f"SELECT * FROM `{self.__table}`"
        conditions = []
        for key, val in search_filter:
            if key not in _cols:
                continue
            if val is None:
                conditions.append(f' `{key}` is null ')
            elif isinstance(val, (list, tuple)):
                index = 0
                in_keys = []
                for _val in val:
                    _key = f'{key}{index}'
                    data[_key] = _val
                    index += 1
                    in_keys.append(f'%({_key})s')

                conditions.append(f' `{key}` in ({",".join(in_keys)}) ')
            else:
                data[key] = val
                conditions.append(f' `{key}` = %({key})s ')
        sql += f" WHERE {conditional.join(conditions)}"

        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            sql += f" ORDER BY {' '.join(order_by)}"
        if limit:
            sql += f' LIMIT {offset},{limit}'

        with mysql_adapter as database:
            results = database.query(sql, data, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            self._load_items(results)

        return self

    def load(self, order_by: list = None, limit: int = 1000, offset: int = 0, cache_key: str = None, ttl_seconds: int = 30):
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        cls = class_()
        sql = f"SELECT * FROM `{self.__table}`"
        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            sql += f" ORDER BY {' '.join(order_by)}"
        if limit:
            sql += f' LIMIT {offset},{limit}'

        with mysql_adapter as database:
            results = database.query(sql, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            self._load_items(results)

        return self

    def distinct(self, column: str, limit: int = 1000, cache_key: str = None, ttl_seconds: int = 300) -> list:
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        cls = class_()
        if column not in cls.cols():
            return []

        sql = f"SELECT DISTINCT(`{column}`) FROM `{self.__table}`"
        if limit:
            sql += f' LIMIT {limit}'

        values = set()
        if cache_key is None:
            cache_key = f'{self.__table}/distinct_{column}'
        with mysql_adapter as database:
            results = database.query(sql, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            for result in results:
                if isinstance(result, dict):
                    for _, val in result.items():
                        values.add(val)

        return list(values)

    def count(self, query_filter: list = None, conditional: str = 'AND', cache_key: str = None, ttl_seconds: int = 5) -> int:
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        sql = f"SELECT COUNT(*) as count FROM `{self.__table}`"
        if isinstance(query_filter, list):
            conditions = []
            for key, val in query_filter:
                if key not in _cols:
                    continue
                if val is None:
                    conditions.append(f' `{key}` is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditions.append(f' `{key}` in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditions.append(f' `{key}` = %({key})s ')
            sql += f" WHERE {conditional.join(conditions)}"

        with mysql_adapter as database:
            res = database.query_one(sql, data, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            return res.get('count', 0)

    def pagination(self, search_filter: list = None, page_size: int = 10, page_num: int = 0, show_pages: int = 10, conditional: str = 'AND', ttl_seconds: int = 5)->dict:
        module = importlib.import_module('trivialsec.models')
        class_ = getattr(module, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        sql = f"SELECT count(*) as records FROM {self.__table}"
        if isinstance(search_filter, list):
            conditions = []
            for col in search_filter:
                key, val = col
                if key not in _cols:
                    continue
                if val is None:
                    conditions.append(f' `{key}` is null ')
                elif isinstance(val, (list, tuple)):
                    index = 0
                    in_keys = []
                    for _val in val:
                        _key = f'{key}{index}'
                        data[_key] = _val
                        index += 1
                        in_keys.append(f'%({_key})s')

                    conditions.append(f' `{key}` in ({",".join(in_keys)}) ')
                else:
                    data[key] = val
                    conditions.append(f' `{key}` = %({key})s ')
            sql += f' WHERE {conditional.join(conditions)} '

        result = None
        with mysql_adapter as database:
            result = database.query_one(sql, data, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            last_page = int(result['records'] / page_size) + 1
            first = min(max(1, page_num-1), max(1, last_page-show_pages))
            last = min(page_num+show_pages-1, last_page+1)
            result['prev'] = max(1, page_num-1)
            result['next'] = min(page_num+1, last_page)
            result['current_page'] = page_num
            result['last_page'] = last_page
            result['page_size'] = page_size
            pages = range(first, last)
            result['pages'] = list(pages)

        return result

    def set_items(self, items: list):
        self.__items = items
        self.__index = 0
        return self

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.__items)

    def __next__(self):
        try:
            result = self.__items[self.__index]
        except IndexError as err:
            self.__index = 0
            raise StopIteration from err
        self.__index += 1
        return result

    def __getitem__(self, item):
        return self.__items[item]

    def to_list(self):
        return self.__items

class DatabaseHelpers:
    __hash__ = object.__hash__

    def __init__(self, table, pk):
        self.__table = table
        self.__pk = pk
        self.__cols = set()

    def hydrate(self, by_column = None, value=None, conditional: str = 'AND', no_cache: bool = False, ttl_seconds: int = 30) -> bool:
        try:
            cache_key = f'{self.__table}/{self.__pk}/{self.__getattribute__(self.__pk)}'
            if by_column is None:
                by_column = self.__pk

            values = {}
            conditionals = '1=1'
            if isinstance(by_column, str):
                conditionals = f' `{by_column}` = %({by_column})s '
                values[by_column] = value if value is not None else self.__getattribute__(by_column)
                cache_key = f'{self.__table}/{by_column}/{values[by_column]}'
            elif isinstance(by_column, tuple):
                by_column, value = by_column
                conditionals = f' `{by_column}` = %({by_column})s '
                values[by_column] = value
                cache_key = f'{self.__table}/{by_column}/{values[by_column]}'
            elif isinstance(by_column, list):
                where = []
                for str_tuple in by_column:
                    if isinstance(str_tuple, tuple):
                        by_column, value = str_tuple
                    if isinstance(str_tuple, str):
                        by_column = str_tuple
                        values[by_column] = value if value is not None else self.__getattribute__(by_column)
                    where.append(f"{by_column} = %({by_column})s")

                conditionals = f' {conditional} '.join(where)
                if self.__pk not in values.keys():
                    cache_parts = [f'table|{self.__table}']
                    for col, dval in values.items():
                        cache_parts.append(f'{col}|{dval}')
                    cache_parts.sort()
                    cache_key = '/'.join(cache_parts)

            sql = f"SELECT * FROM `{self.__table}` WHERE {conditionals} LIMIT 1"
            with mysql_adapter as database:
                result = database.query_one(sql, values, cache_key=None if no_cache is True else cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
                if isinstance(result, dict):
                    for col, val in result.items():
                        setattr(self, col, val)

        except Exception as ex:
            logger.error(ex)
            return False

        return True

    def exists(self, by_list: list = None, conditional: str = 'AND') -> bool:
        value = self.__getattribute__(self.__pk)
        with mysql_adapter as database:
            if not by_list:
                if not value:
                    logger.debug(f'Not exists {repr(self.__dict__)}')
                    return False
                pk_column = self.__pk
                sql = f"SELECT `{self.__pk}` FROM `{self.__table}` WHERE `{pk_column}` = %({pk_column})s LIMIT 1"
                value = value if value is not None else self.__getattribute__(pk_column)
                result = database.query_one(sql, {pk_column: value})
                if result is not None:
                    setattr(self, self.__pk, result[self.__pk])
                    return True
            if isinstance(by_list, list):
                where = []
                values = {}
                for str_tuple in by_list:
                    pk_column = str_tuple
                    value = None
                    if isinstance(str_tuple, tuple):
                        pk_column, value = str_tuple
                    where.append(f"`{pk_column}` = %({pk_column})s")
                    value = value if value is not None else self.__getattribute__(pk_column)
                    values[pk_column] = value
                conditionals = f' {conditional} '.join(where)
                sql = f"SELECT `{self.__pk}` FROM `{self.__table}` WHERE {conditionals} LIMIT 1"
                result = database.query_one(sql, values)
                if result is not None:
                    setattr(self, self.__pk, result[self.__pk])
                    return True

        return False

    def persist(self, exists=None, invalidations: list = None) -> bool:
        data = {}
        values = []
        columns = []
        if invalidations is None:
            invalidations = []
        if exists is None:
            exists = False if self.__getattribute__(self.__pk) is None else self.exists()
        logger.debug(f'persist {"UPDATE" if exists else "INSERT"} {self.__table} {self.__pk}')
        inv1 = f'{self.__table}/cols'
        if inv1 not in invalidations:
            invalidations.append(inv1)

        for prop in self.cols():
            _val = self.__getattribute__(prop)
            if not exists and _val is None:
                continue
            if isinstance(_val, bool):
                data[prop] = 1 if _val is True else 0
            elif isinstance(_val, datetime):
                data[prop] = _val.isoformat()
            elif _val is not None and isinstance(_val, object):
                data[prop] = str(_val)
            else:
                data[prop] = _val
            inv2 = f'{self.__table}/{prop}/{data[prop]}'
            if inv2 not in invalidations:
                invalidations.append(inv2)

        if self.__pk in data.keys():
            inv3 = f'{self.__table}/{self.__pk}/{data[self.__pk]}'
            if inv3 not in invalidations:
                invalidations.append(inv3)

        with mysql_adapter as database:
            if exists is True:
                for col, _ in data.items():
                    try:
                        self.__getattribute__(col)
                    except (KeyError, AttributeError):
                        continue
                    if col != self.__pk:
                        values.append(f'`{col}` = %({col})s')
                update_stmt = f"UPDATE `{self.__table}` SET {', '.join(values)} WHERE `{self.__pk}` = %({self.__pk})s"
                logger.info(f'{update_stmt} {repr(data)}')
                changed = database.query(update_stmt, data, invalidations=invalidations)
                if changed > 0:
                    return True
            if exists is False:
                for col, _ in data.items():
                    if _ is None:
                        continue
                    try:
                        self.__getattribute__(col)
                    except (KeyError, AttributeError):
                        continue
                    values.append(f'%({col})s')
                    columns.append(col)

                insert_stmt = f"INSERT INTO `{self.__table}` (`{'`, `'.join(columns)}`) VALUES ({', '.join(values)})"
                logger.info(f'{insert_stmt} {repr(data)}')
                new_id = database.query(insert_stmt, data, invalidations=invalidations)
                if new_id:
                    setattr(self, self.__pk, new_id)
                    self.hydrate()
                    return True

        return False

    def cols(self, ttl_seconds: int = 3600) -> list:
        if self.__cols:
            return self.__cols
        with mysql_adapter as database:
            result_cols = database.table_cols(self.__table, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            columns = set()
            for prop in result_cols:
                try:
                    self.__getattribute__(prop)
                except (KeyError, AttributeError):
                    continue
                columns.add(prop)
            self.__cols = list(columns)
            return self.__cols
