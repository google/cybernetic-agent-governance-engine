from typing import Any, Sequence

class EngineResult:
    text: str

class AnonymizerEngine:
    def __init__(self, **kwargs: Any) -> None: ...
    def anonymize(
        self,
        text: str,
        analyzer_results: Sequence[Any],
        **kwargs: Any,
    ) -> EngineResult: ...

