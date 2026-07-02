from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CheckAccessRequest(_message.Message):
    __slots__ = ("tenant_id", "subject_id", "action", "resource_id", "scope")
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    tenant_id: str
    subject_id: str
    action: str
    resource_id: str
    scope: str
    def __init__(self, tenant_id: _Optional[str] = ..., subject_id: _Optional[str] = ..., action: _Optional[str] = ..., resource_id: _Optional[str] = ..., scope: _Optional[str] = ...) -> None: ...

class CheckAccessResponse(_message.Message):
    __slots__ = ("allowed", "deny_reason")
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    DENY_REASON_FIELD_NUMBER: _ClassVar[int]
    allowed: bool
    deny_reason: str
    def __init__(self, allowed: bool = ..., deny_reason: _Optional[str] = ...) -> None: ...

class BatchCheckAccessRequest(_message.Message):
    __slots__ = ("requests",)
    REQUESTS_FIELD_NUMBER: _ClassVar[int]
    requests: _containers.RepeatedCompositeFieldContainer[CheckAccessRequest]
    def __init__(self, requests: _Optional[_Iterable[_Union[CheckAccessRequest, _Mapping]]] = ...) -> None: ...

class BatchCheckAccessResponse(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[CheckAccessResponse]
    def __init__(self, results: _Optional[_Iterable[_Union[CheckAccessResponse, _Mapping]]] = ...) -> None: ...
