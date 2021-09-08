__module__ = 'trivialsec.exceptions'


class AppError(Exception):
    pass

class DatabaseError(Exception):
    pass

class ValidationError(ValueError):
    pass
