from typing import Any

class RecognizerResult:
    entity_type: str
    start: int
    end: int
    score: float

class AnalyzerEngine:
    def __init__(self, nlp_engine: Any | None = ..., **kwargs: Any) -> None: ...
    def analyze(
        self,
        text: str,
        language: str,
        entities: list[str] | None = ...,
        correlation_id: str | None = ...,
        score_threshold: float | None = ...,
        return_decision_process: bool = ...,
        **kwargs: Any,
    ) -> list[RecognizerResult]: ...
