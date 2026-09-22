from collections.abc import Callable
from typing import Any, TypeVar

_F = TypeVar("_F", bound=Callable[..., Any])

def action(name: str | None = ...) -> Callable[[_F], _F]: ...
