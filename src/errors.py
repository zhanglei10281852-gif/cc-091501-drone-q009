"""统一的领域/接口错误。"""


class ApiError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.message = message
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code


class AuthError(ApiError):
    status = 401
    code = "unauthorized"


class PermissionError(ApiError):  # noqa: A001 - 领域内语义明确
    status = 403
    code = "forbidden"


class NotFoundError(ApiError):
    status = 404
    code = "not_found"


class ConflictError(ApiError):
    status = 409
    code = "conflict"


class UnprocessableError(ApiError):
    status = 422
    code = "unprocessable"
