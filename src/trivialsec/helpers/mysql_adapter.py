import importlib
from datetime import datetime, timedelta
from gunicorn.glogging import logging
from .mysql import MySQL


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.mysql_adapter'
__models_module__ = importlib.import_module('trivialsec.models')

main_adapter = MySQL(read_replica=False)
replica_adapter = MySQL()

class MySQL_Table_Adapter:
    def __init__(self, class_name, table, primary_key):
        self.__class_name = class_name
        self.__table = table
        self.__pk = primary_key
        self.__index = 0
        self.__items = []

    def _load_items(self, results :list):
        class_ = getattr(__models_module__, self.__class_name)
        for result in results:
            model = class_()
            for col, val in result.items():
                setattr(model, col, val)
            self.__items.append(model)
        self.__index = 0

    def find_by(self, search_filter :list, conditional :str = 'AND', order_by :list = None, limit: int = 1000, offset: int = 0, cache_key :str = None, ttl_seconds: int = 30):
        class_ = getattr(__models_module__, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        stmt = f"SELECT * FROM `{self.__table}`"
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
        stmt += f" WHERE {conditional.join(conditions)}"

        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            stmt += f" ORDER BY {' '.join(order_by)}"
        if limit:
            stmt += f' LIMIT {offset},{limit}'

        with replica_adapter as sql:
            results = sql.query(stmt, data, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            self._load_items(results)

        return self

    def load(self, order_by :list = None, limit: int = 1000, offset: int = 0, cache_key :str = None, ttl_seconds: int = 30):
        class_ = getattr(__models_module__, self.__class_name)
        cls = class_()
        stmt = f"SELECT * FROM `{self.__table}`"
        if order_by and isinstance(order_by, list):
            for _order in order_by:
                if _order.lower() in ['DESC', 'ASC'] or _order.lower() not in cls.cols():
                    continue
            stmt += f" ORDER BY {' '.join(order_by)}"
        if limit:
            stmt += f' LIMIT {offset},{limit}'

        with replica_adapter as sql:
            results = sql.query(stmt, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            self._load_items(results)

        return self

    def distinct(self, column :str, limit: int = 1000, cache_key :str = None, ttl_seconds: int = 300) -> list:
        class_ = getattr(__models_module__, self.__class_name)
        cls = class_()
        if column not in cls.cols():
            return []

        stmt = f"SELECT DISTINCT(`{column}`) FROM `{self.__table}`"
        if limit:
            stmt += f' LIMIT {limit}'

        values = set()
        if cache_key is None:
            cache_key = f'{self.__table}/distinct_{column}'
        with replica_adapter as sql:
            results = sql.query(stmt, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            for result in results:
                if isinstance(result, dict):
                    for _, val in result.items():
                        values.add(val)

        return list(values)

    def count(self, query_filter :list = None, conditional :str = 'AND', cache_key :str = None, ttl_seconds: int = 5) -> int:
        class_ = getattr(__models_module__, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        stmt = f"SELECT COUNT({self.__pk}) as count FROM `{self.__table}`"
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
            stmt += f" WHERE {conditional.join(conditions)}"

        with replica_adapter as sql:
            res = sql.query_one(stmt, data, cache_key=cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            return res.get('count', 0)

    def pagination(self, search_filter :list = None, page_size: int = 10, page_num: int = 0, show_pages: int = 10, conditional :str = 'AND', ttl_seconds: int = 5)->dict:
        class_ = getattr(__models_module__, self.__class_name)
        cls = class_()
        _cols = cls.cols()
        data = {}
        stmt = f"SELECT count({self.__pk}) as records FROM {self.__table}"
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
            stmt += f' WHERE {conditional.join(conditions)} '

        result = None
        with replica_adapter as sql:
            result = sql.query_one(stmt, data, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
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

    def set_items(self, items :list):
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

class MySQL_Row_Adapter:
    __hash__ = object.__hash__

    def __init__(self, table, pk):
        self.__table = table
        self.__pk = pk
        self.__cols = set()

    def hydrate(self, by_column = None, value=None, conditional :str = 'AND', no_cache :bool = False, ttl_seconds: int = 30) -> bool:
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

            stmt = f"SELECT * FROM `{self.__table}` WHERE {conditionals} LIMIT 1"
            with replica_adapter as sql:
                result = sql.query_one(stmt, values, cache_key=None if no_cache is True else cache_key, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
                if isinstance(result, dict):
                    for col, val in result.items():
                        setattr(self, col, val)

        except Exception as ex:
            logger.error(ex)
            return False

        return True

    def exists(self, by_list :list = None, conditional :str = 'AND') -> bool:
        value = self.__getattribute__(self.__pk)
        with replica_adapter as sql:
            if not by_list:
                if not value:
                    logger.debug(f'Not exists {repr(self.__dict__)}')
                    return False
                pk_column = self.__pk
                stmt = f"SELECT `{self.__pk}` FROM `{self.__table}` WHERE `{pk_column}` = %({pk_column})s LIMIT 1"
                value = value if value is not None else self.__getattribute__(pk_column)
                result = sql.query_one(stmt, {pk_column: value})
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
                stmt = f"SELECT `{self.__pk}` FROM `{self.__table}` WHERE {conditionals} LIMIT 1"
                result = sql.query_one(stmt, values)
                if result is not None:
                    setattr(self, self.__pk, result[self.__pk])
                    return True

        return False

    def persist(self, exists=None, invalidations :list = None) -> bool:
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

        with main_adapter as sql:
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
                changed = sql.query(update_stmt, data, invalidations=invalidations)
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
                new_id = sql.query(insert_stmt, data, invalidations=invalidations)
                if new_id:
                    setattr(self, self.__pk, new_id)
                    self.hydrate()
                    return True

        return False

    def cols(self, ttl_seconds: int = 3600) -> list:
        if self.__cols:
            return self.__cols
        with replica_adapter as sql:
            result_cols = sql.table_cols(self.__table, cache_ttl=None if ttl_seconds is None else timedelta(seconds=ttl_seconds))
            columns = set()
            for prop in result_cols:
                try:
                    self.__getattribute__(prop)
                except (KeyError, AttributeError):
                    continue
                columns.add(prop)
            self.__cols = list(columns)
            return self.__cols

    def delete(self, invalidations :list = None) -> bool:
        data = {}
        if self.__getattribute__(self.__pk) is None:
            return False
        if invalidations is None:
            invalidations = []

        data[self.__pk] = self.__getattribute__(self.__pk)
        inv1 = f'{self.__table}/cols'
        if inv1 not in invalidations:
            invalidations.append(inv1)
        inv2 = f'{self.__table}/{self.__pk}/{data[self.__pk]}'
        if inv2 not in invalidations:
            invalidations.append(inv2)

        with main_adapter as sql:
            stmt = f"DELETE FROM `{self.__table}` WHERE `{self.__pk}` = %({self.__pk})s LIMIT 1"
            logger.info(f'{stmt} {repr(data)}')
            changed = sql.query(stmt, data, invalidations=invalidations)
            if changed == 1:
                return True

        return False
