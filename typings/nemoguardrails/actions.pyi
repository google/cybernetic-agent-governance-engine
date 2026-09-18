from typing import Any, Callable, TypeVar

_F = TypeVar("_F", bound=Callable[..., Any])

def action(name: str | None = ...) -> Callable[[_F], _F]: ...

