# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Adapter-Driven Live Rollout Runner & Tokenomics Engine (`src/eval_harness/runner.py`).

Adapts the decoupled runner and adapter pattern from ``agent-eval-framework``
into CAGE's offline evaluation plane without coupling to cloud-only SDKs
(``vertexai.preview.evaluation.EvalTask`` or ``google.cloud.storage``):
1. Provides pluggable rollout adapters (:class:`CallableRolloutAdapter`,
   :class:`ADKSessionRolloutAdapter`, :class:`MultiAgentRolloutAdapter`, and
   :class:`HttpRolloutAdapter`) that execute live or simulated agents and emit
   canonical :class:`~src.eval_harness.harness.ATIFTrajectory` artifacts.
2. Automates paired differential rollouts (``baseline`` vs. ``with_skill`` in
   both ``isolation`` and ``group`` decoy modes) for any sequence of
   :class:`~src.eval_harness.harness.SkillEvalCase` items.
3. Computes per-trajectory tokenomics (:func:`compute_trajectory_tokenomics` and
   :func:`compute_cost_savings_multiplier`), including multi-turn token growth
   rate and quadratic context-bloat detection.
"""

from __future__ import annotations

import importlib
import inspect
import json
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from src.eval_harness.adapters import adk_session_to_atif
from src.eval_harness.harness import (
    ATIFStep,
    ATIFTrajectory,
    FoundationModelEvalHarness,
    ShadowStateReducer,
    SkillEvalCase,
    SkillLiftReport,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Tokenomics & Multi-Turn Token Growth Metrics
# ---------------------------------------------------------------------------

MODEL_PRICING_CATALOG: dict[str, dict[str, float]] = {
    "gemini-3.7-flash": {
        "input_per_1m": 0.075,
        "output_per_1m": 0.30,
        "cached_input_per_1m": 0.01875,
    },
    "gemini-3.5-flash": {
        "input_per_1m": 0.075,
        "output_per_1m": 0.30,
        "cached_input_per_1m": 0.01875,
    },
    "gemini-2.5-flash": {
        "input_per_1m": 0.075,
        "output_per_1m": 0.30,
        "cached_input_per_1m": 0.01875,
    },
    "gemini-2.5-pro": {
        "input_per_1m": 1.25,
        "output_per_1m": 5.00,
        "cached_input_per_1m": 0.3125,
    },
    "claude-3-7-sonnet": {
        "input_per_1m": 3.00,
        "output_per_1m": 15.00,
        "cached_input_per_1m": 0.30,
    },
    "gpt-4o": {
        "input_per_1m": 2.50,
        "output_per_1m": 10.00,
        "cached_input_per_1m": 1.25,
    },
    "gpt-4o-mini": {
        "input_per_1m": 0.15,
        "output_per_1m": 0.60,
        "cached_input_per_1m": 0.075,
    },
}


@dataclass(frozen=True)
class TrajectoryTokenomics:
    """Token usage, USD execution cost, and multi-turn growth summary for a trajectory."""

    trajectory_id: str
    model_id: str
    total_prompt_tokens: int
    total_completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    multi_turn_growth_rate: float
    is_quadratic_bloat: bool


def estimate_token_count(content: Any) -> int:
    """Estimate token count using the standard ~4 characters per token heuristic."""
    if content is None:
        return 0
    if isinstance(content, (Mapping, Sequence)) and not isinstance(
        content, (str, bytes)
    ):
        text = json.dumps(content, ensure_ascii=False, default=str)
    else:
        text = str(content)
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def compute_trajectory_tokenomics(
    trajectory: ATIFTrajectory,
    *,
    quadratic_growth_threshold: float = 2.5,
) -> TrajectoryTokenomics:
    """Compute token usage, USD cost, and multi-turn token growth rate for ``trajectory``."""
    step_prompt_tokens: list[int] = []
    step_completion_tokens: list[int] = []

    running_context_tokens = estimate_token_count(trajectory.prompt)
    for step in trajectory.steps:
        meta = step.metadata or {}
        explicit_prompt = meta.get("prompt_tokens")
        explicit_completion = meta.get("completion_tokens")

        turn_output_est = estimate_token_count(step.message) + estimate_token_count(
            step.tool_calls
        )
        turn_obs_est = estimate_token_count(step.observation)

        p_tok = (
            int(explicit_prompt)
            if isinstance(explicit_prompt, (int, float))
            else running_context_tokens
        )
        c_tok = (
            int(explicit_completion)
            if isinstance(explicit_completion, (int, float))
            else turn_output_est
        )
        step_prompt_tokens.append(max(1, p_tok))
        step_completion_tokens.append(max(0, c_tok))
        running_context_tokens += turn_output_est + turn_obs_est

    if not step_prompt_tokens:
        total_prompt = estimate_token_count(trajectory.prompt)
        total_completion = estimate_token_count(trajectory.final_response)
        growth_rate = 1.0
    else:
        total_prompt = sum(step_prompt_tokens)
        total_completion = sum(step_completion_tokens) + estimate_token_count(
            trajectory.final_response
        )
        if len(step_prompt_tokens) >= 2 and step_prompt_tokens[0] > 0:
            growth_rate = round(step_prompt_tokens[-1] / step_prompt_tokens[0], 4)
        else:
            growth_rate = 1.0

    pricing = MODEL_PRICING_CATALOG.get(
        trajectory.model_id,
        {"input_per_1m": 0.075, "output_per_1m": 0.30},
    )
    cost_usd = (total_prompt / 1_000_000.0) * pricing["input_per_1m"] + (
        total_completion / 1_000_000.0
    ) * pricing["output_per_1m"]

    return TrajectoryTokenomics(
        trajectory_id=trajectory.trajectory_id,
        model_id=trajectory.model_id,
        total_prompt_tokens=total_prompt,
        total_completion_tokens=total_completion,
        total_tokens=total_prompt + total_completion,
        estimated_cost_usd=round(cost_usd, 8),
        multi_turn_growth_rate=growth_rate,
        is_quadratic_bloat=(
            len(step_prompt_tokens) >= 2 and growth_rate > quadratic_growth_threshold
        ),
    )


def compute_cost_savings_multiplier(
    reference_cost_usd: float,
    candidate_cost_usd: float,
) -> float:
    """Return the cost advantage multiplier (`reference_cost_usd / candidate_cost_usd`)."""
    if candidate_cost_usd <= 0.0:
        return 1.0 if reference_cost_usd <= 0.0 else float("inf")
    return round(reference_cost_usd / candidate_cost_usd, 4)


# ---------------------------------------------------------------------------
# Rollout Workspace Context & Pluggable Adapter Hierarchy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RolloutWorkspaceContext:
    """Execution context injected into an adapter for a single evaluation rollout."""

    case_id: str
    prompt: str
    mode: str = "baseline"
    visible_skills: tuple[str, ...] = ()
    skill_markdown_by_name: dict[str, str] = field(default_factory=dict)
    initial_shadow_state: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def _resolve_symbol(target: str) -> Any:
    """Dynamically import ``module.path:attr`` or ``module.path.Attr``."""
    sep = ":" if ":" in target else "."
    if sep not in target:
        raise ValueError(
            f"Target {target!r} must be a qualified 'module:symbol' or 'module.Symbol' path"
        )
    module_path, attr_name = target.rsplit(sep, 1)
    module = importlib.import_module(module_path)
    return getattr(module, attr_name)


def _normalize_raw_output_to_atif(
    raw_output: Any,
    *,
    trajectory_id: str,
    harness_id: str,
    model_id: str,
    prompt: str,
    visible_skills: tuple[str, ...] = (),
) -> ATIFTrajectory:
    """Convert heterogeneous adapter return payloads into a canonical :class:`ATIFTrajectory`."""
    if isinstance(raw_output, ATIFTrajectory):
        return ATIFTrajectory(
            trajectory_id=raw_output.trajectory_id or trajectory_id,
            harness_id=raw_output.harness_id or harness_id,
            model_id=raw_output.model_id or model_id,
            prompt=raw_output.prompt or prompt,
            steps=raw_output.steps,
            final_response=raw_output.final_response,
            intermediate_artifacts=raw_output.intermediate_artifacts,
            visible_skills=raw_output.visible_skills or visible_skills,
        )

    if isinstance(raw_output, str):
        return ATIFTrajectory(
            trajectory_id=trajectory_id,
            harness_id=harness_id,
            model_id=model_id,
            prompt=prompt,
            steps=(),
            final_response=raw_output,
            visible_skills=visible_skills,
        )

    if isinstance(raw_output, Mapping):
        if "events" in raw_output and "steps" not in raw_output:
            session_dict = dict(raw_output)
            session_dict.setdefault("trajectory_id", trajectory_id)
            session_dict.setdefault("model_id", model_id)
            session_dict.setdefault("prompt", prompt)
            session_dict.setdefault("visible_skills", list(visible_skills))
            return adk_session_to_atif(session_dict, default_model_id=model_id)

        if "steps" in raw_output:
            payload = dict(raw_output)
            payload.setdefault("trajectory_id", trajectory_id)
            payload.setdefault("harness_id", harness_id)
            payload.setdefault("model_id", model_id)
            payload.setdefault("prompt", prompt)
            payload.setdefault("visible_skills", list(visible_skills))
            return ATIFTrajectory.from_dict(payload)

        # Normalize `agent-eval` style `{response/actual_response, trajectory/predicted_trajectory}`
        final_resp = str(
            raw_output.get("final_response")
            or raw_output.get("actual_response")
            or raw_output.get("response")
            or ""
        )
        raw_traj = (
            raw_output.get("predicted_trajectory") or raw_output.get("trajectory") or ()
        )
        steps: list[ATIFStep] = []
        for idx, item in enumerate(raw_traj, start=1):
            if not isinstance(item, Mapping):
                continue
            if "tool_calls" in item:
                tcalls = tuple(
                    dict(tc)
                    for tc in (item.get("tool_calls") or ())
                    if isinstance(tc, Mapping)
                )
            else:
                tname = str(item.get("tool_name") or item.get("name") or "unknown_tool")
                targs = item.get("tool_input") or item.get("arguments") or {}
                tcalls = (
                    {
                        "name": tname,
                        "arguments": dict(targs) if isinstance(targs, Mapping) else {},
                    },
                )
            meta = dict(item.get("metadata") or {})
            if "sub_agent" in item:
                meta["sub_agent"] = str(item["sub_agent"])
            steps.append(
                ATIFStep(
                    step_index=int(item.get("step_index", idx)),
                    source=str(item.get("source") or item.get("sub_agent") or "agent"),
                    message=str(item.get("message") or item.get("thought") or ""),
                    tool_calls=tcalls,
                    observation=str(
                        item.get("observation") or item.get("tool_output") or ""
                    ),
                    metadata=meta,
                )
            )
        raw_artifacts = raw_output.get("intermediate_artifacts") or raw_output.get(
            "artifacts"
        )
        artifacts = (
            {str(k): str(v) for k, v in raw_artifacts.items()}
            if isinstance(raw_artifacts, Mapping)
            else {}
        )
        return ATIFTrajectory(
            trajectory_id=str(raw_output.get("trajectory_id") or trajectory_id),
            harness_id=str(raw_output.get("harness_id") or harness_id),
            model_id=str(raw_output.get("model_id") or model_id),
            prompt=prompt,
            steps=tuple(steps),
            final_response=final_resp,
            intermediate_artifacts=artifacts,
            visible_skills=visible_skills,
        )

    raise TypeError(
        f"Unsupported rollout adapter output type: {type(raw_output).__name__}"
    )


class BaseRolloutAdapter(ABC):
    """Abstract base class for live/simulated agent rollout adapters."""

    def __init__(
        self,
        *,
        harness_id: str = "cage-rollout",
        model_id: str = "gemini-3.5-flash",
    ) -> None:
        self.harness_id = harness_id
        self.model_id = model_id

    @abstractmethod
    async def rollout(
        self,
        prompt: str,
        *,
        workspace: RolloutWorkspaceContext | None = None,
    ) -> ATIFTrajectory:
        """Execute a single agent rollout for ``prompt`` under ``workspace``."""


class CallableRolloutAdapter(BaseRolloutAdapter):
    """Wraps a Python function, LangGraph callable, or dot-path target into a rollout adapter."""

    def __init__(
        self,
        target: Callable[..., Any] | str,
        *,
        harness_id: str = "callable-adapter",
        model_id: str = "gemini-3.5-flash",
    ) -> None:
        super().__init__(harness_id=harness_id, model_id=model_id)
        self._fn: Callable[..., Any] = (
            _resolve_symbol(target) if isinstance(target, str) else target
        )
        sig = inspect.signature(self._fn)
        self._accepts_workspace = "workspace" in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

    async def rollout(
        self,
        prompt: str,
        *,
        workspace: RolloutWorkspaceContext | None = None,
    ) -> ATIFTrajectory:
        ws = workspace or RolloutWorkspaceContext(case_id="adhoc", prompt=prompt)
        if self._accepts_workspace:
            raw = self._fn(prompt, workspace=ws)
        else:
            raw = self._fn(prompt)
        if inspect.isawaitable(raw):
            raw = await raw
        traj_id = f"{ws.case_id}-{ws.mode}"
        return _normalize_raw_output_to_atif(
            raw,
            trajectory_id=traj_id,
            harness_id=self.harness_id,
            model_id=self.model_id,
            prompt=prompt,
            visible_skills=ws.visible_skills,
        )


class ADKSessionRolloutAdapter(BaseRolloutAdapter):
    """Adapter for Google ADK agents or session factories returning ADK event payloads."""

    def __init__(
        self,
        session_runner: Callable[..., Any] | str,
        *,
        model_id: str = "gemini-3.5-flash",
    ) -> None:
        super().__init__(harness_id="google-adk", model_id=model_id)
        self._runner: Callable[..., Any] = (
            _resolve_symbol(session_runner)
            if isinstance(session_runner, str)
            else session_runner
        )
        sig = inspect.signature(self._runner)
        self._accepts_workspace = "workspace" in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

    async def rollout(
        self,
        prompt: str,
        *,
        workspace: RolloutWorkspaceContext | None = None,
    ) -> ATIFTrajectory:
        ws = workspace or RolloutWorkspaceContext(case_id="adk", prompt=prompt)
        if self._accepts_workspace:
            raw_session = self._runner(prompt, workspace=ws)
        else:
            raw_session = self._runner(prompt)
        if inspect.isawaitable(raw_session):
            raw_session = await raw_session
        return _normalize_raw_output_to_atif(
            raw_session,
            trajectory_id=f"{ws.case_id}-{ws.mode}",
            harness_id=self.harness_id,
            model_id=self.model_id,
            prompt=prompt,
            visible_skills=ws.visible_skills,
        )


class MultiAgentRolloutAdapter(BaseRolloutAdapter):
    """Adapter for hierarchical / sequential Multi-Agent Systems (MAS).

    Records specialist sub-agent delegations in ``ATIFStep.metadata["sub_agent"]``
    so CAGE's routing discipline and Routing Premium scorers can evaluate
    sub-agent routing alongside ``SKILL.md`` activation.
    """

    def __init__(
        self,
        coordinator: Callable[..., Any] | str,
        *,
        sub_agents: Sequence[str] = (),
        topology: str = "hierarchical",
        model_id: str = "gemini-3.5-flash",
    ) -> None:
        super().__init__(harness_id=f"mas-{topology}", model_id=model_id)
        self._coordinator: Callable[..., Any] = (
            _resolve_symbol(coordinator)
            if isinstance(coordinator, str)
            else coordinator
        )
        self.sub_agents = tuple(sub_agents)
        self.topology = topology
        sig = inspect.signature(self._coordinator)
        self._accepts_workspace = "workspace" in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

    async def rollout(
        self,
        prompt: str,
        *,
        workspace: RolloutWorkspaceContext | None = None,
    ) -> ATIFTrajectory:
        ws = workspace or RolloutWorkspaceContext(
            case_id="mas",
            prompt=prompt,
            visible_skills=self.sub_agents,
        )
        effective_ws = RolloutWorkspaceContext(
            case_id=ws.case_id,
            prompt=ws.prompt,
            mode=ws.mode,
            visible_skills=ws.visible_skills or self.sub_agents,
            skill_markdown_by_name=ws.skill_markdown_by_name,
            initial_shadow_state=ws.initial_shadow_state,
            metadata={
                **ws.metadata,
                "topology": self.topology,
                "registered_sub_agents": list(self.sub_agents),
            },
        )
        if self._accepts_workspace:
            raw = self._coordinator(prompt, workspace=effective_ws)
        else:
            raw = self._coordinator(prompt)
        if inspect.isawaitable(raw):
            raw = await raw
        return _normalize_raw_output_to_atif(
            raw,
            trajectory_id=f"{ws.case_id}-{ws.mode}",
            harness_id=self.harness_id,
            model_id=self.model_id,
            prompt=prompt,
            visible_skills=effective_ws.visible_skills,
        )


class HttpRolloutAdapter(BaseRolloutAdapter):
    """Adapter for remote deployed HTTP / REST / A2A agent endpoints."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float = 30.0,
        model_id: str = "gemini-3.5-flash",
    ) -> None:
        super().__init__(harness_id="http-agent", model_id=model_id)
        parsed = urlparse(endpoint_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"HttpRolloutAdapter requires an explicit http:// or https:// URL; got {endpoint_url!r}"
            )
        self.endpoint_url = endpoint_url
        self.headers = dict(headers or {})
        self.timeout_seconds = timeout_seconds

    async def rollout(
        self,
        prompt: str,
        *,
        workspace: RolloutWorkspaceContext | None = None,
    ) -> ATIFTrajectory:
        ws = workspace or RolloutWorkspaceContext(case_id="http", prompt=prompt)
        body = json.dumps(
            {
                "prompt": prompt,
                "case_id": ws.case_id,
                "mode": ws.mode,
                "visible_skills": list(ws.visible_skills),
                "initial_shadow_state": dict(ws.initial_shadow_state),
            }
        ).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(
            self.endpoint_url,
            data=body,
            headers=req_headers,
            method="POST",
        )
        # Bandit B310 compliance: scheme is strictly validated to http/https in __init__
        if not self.endpoint_url.startswith(("http://", "https://")):
            raise ValueError("Unsupported URL scheme")
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # nosec B310
            raw_bytes = resp.read()
        payload = json.loads(raw_bytes.decode("utf-8"))
        return _normalize_raw_output_to_atif(
            payload,
            trajectory_id=f"{ws.case_id}-{ws.mode}",
            harness_id=self.harness_id,
            model_id=self.model_id,
            prompt=prompt,
            visible_skills=ws.visible_skills,
        )


def load_rollout_adapter(
    adapter_spec: str,
    config: Mapping[str, Any] | None = None,
) -> BaseRolloutAdapter:
    """Instantiate a :class:`BaseRolloutAdapter` from a dot/colon path and optional config.

    If ``adapter_spec`` resolves to a :class:`BaseRolloutAdapter` subclass, it is
    instantiated with ``**config``. If it resolves to a plain function or callable,
    it is automatically wrapped in :class:`CallableRolloutAdapter`.
    """
    cfg = dict(config or {})
    symbol = _resolve_symbol(adapter_spec)
    if isinstance(symbol, type) and issubclass(symbol, BaseRolloutAdapter):
        return symbol(**cfg)
    if callable(symbol):
        return CallableRolloutAdapter(symbol, **cfg)
    raise TypeError(
        f"Resolved symbol {adapter_spec!r} is neither a BaseRolloutAdapter subclass nor callable"
    )


# ---------------------------------------------------------------------------
# Paired Differential Rollout Runner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PairedRolloutBundle:
    """Generated ATIF trajectory maps and tokenomics from a paired rollout run."""

    skill_name: str
    model_id: str
    baseline_trajectories: dict[str, ATIFTrajectory]
    with_skill_trajectories: dict[str, ATIFTrajectory]
    group_baseline_trajectories: dict[str, ATIFTrajectory] | None = None
    group_with_skill_trajectories: dict[str, ATIFTrajectory] | None = None
    baseline_tokenomics: dict[str, TrajectoryTokenomics] = field(default_factory=dict)
    with_skill_tokenomics: dict[str, TrajectoryTokenomics] = field(default_factory=dict)


class AgentRolloutRunner:
    """Executes paired (baseline vs. with-skill) agent rollouts and produces ATIF bundles."""

    def __init__(self, adapter: BaseRolloutAdapter) -> None:
        self._adapter = adapter

    @property
    def adapter(self) -> BaseRolloutAdapter:
        return self._adapter

    async def run_paired_rollouts(
        self,
        cases: Sequence[SkillEvalCase],
        *,
        skill_name: str,
        skill_md_path: Path | None = None,
        decoy_skills: Sequence[str] = (),
    ) -> PairedRolloutBundle:
        """Run each :class:`SkillEvalCase` in baseline, with-skill, and optional group decoy modes."""
        skill_md_map: dict[str, str] = {}
        if skill_md_path is not None and skill_md_path.exists():
            skill_md_map[skill_name] = skill_md_path.read_text(encoding="utf-8")

        baseline_map: dict[str, ATIFTrajectory] = {}
        with_skill_map: dict[str, ATIFTrajectory] = {}
        group_base_map: dict[str, ATIFTrajectory] | None = {} if decoy_skills else None
        group_skill_map: dict[str, ATIFTrajectory] | None = {} if decoy_skills else None
        base_tok_map: dict[str, TrajectoryTokenomics] = {}
        skill_tok_map: dict[str, TrajectoryTokenomics] = {}

        for case in cases:
            base_ws = RolloutWorkspaceContext(
                case_id=case.case_id,
                prompt=case.prompt,
                mode="baseline_iso",
                visible_skills=(),
                skill_markdown_by_name={},
                initial_shadow_state=dict(case.initial_shadow_state),
                metadata={"bucket": case.bucket.value},
            )
            base_traj = await self._adapter.rollout(case.prompt, workspace=base_ws)
            baseline_map[case.case_id] = base_traj
            base_tok_map[case.case_id] = compute_trajectory_tokenomics(base_traj)

            iso_skills = (skill_name, *case.allowed_skills)
            dedup_iso_skills = tuple(dict.fromkeys(s for s in iso_skills if s))
            skill_ws = RolloutWorkspaceContext(
                case_id=case.case_id,
                prompt=case.prompt,
                mode="with_skill_iso",
                visible_skills=dedup_iso_skills,
                skill_markdown_by_name=dict(skill_md_map),
                initial_shadow_state=dict(case.initial_shadow_state),
                metadata={"bucket": case.bucket.value},
            )
            skill_traj = await self._adapter.rollout(case.prompt, workspace=skill_ws)
            with_skill_map[case.case_id] = skill_traj
            skill_tok_map[case.case_id] = compute_trajectory_tokenomics(skill_traj)

            if (
                decoy_skills
                and group_base_map is not None
                and group_skill_map is not None
            ):
                grp_base_ws = RolloutWorkspaceContext(
                    case_id=case.case_id,
                    prompt=case.prompt,
                    mode="baseline_group",
                    visible_skills=tuple(decoy_skills),
                    skill_markdown_by_name={},
                    initial_shadow_state=dict(case.initial_shadow_state),
                    metadata={"bucket": case.bucket.value},
                )
                group_base_map[case.case_id] = await self._adapter.rollout(
                    case.prompt, workspace=grp_base_ws
                )

                grp_skills = tuple(dict.fromkeys((*dedup_iso_skills, *decoy_skills)))
                grp_skill_ws = RolloutWorkspaceContext(
                    case_id=case.case_id,
                    prompt=case.prompt,
                    mode="with_skill_group",
                    visible_skills=grp_skills,
                    skill_markdown_by_name=dict(skill_md_map),
                    initial_shadow_state=dict(case.initial_shadow_state),
                    metadata={"bucket": case.bucket.value},
                )
                group_skill_map[case.case_id] = await self._adapter.rollout(
                    case.prompt, workspace=grp_skill_ws
                )

        return PairedRolloutBundle(
            skill_name=skill_name,
            model_id=self._adapter.model_id,
            baseline_trajectories=baseline_map,
            with_skill_trajectories=with_skill_map,
            group_baseline_trajectories=group_base_map,
            group_with_skill_trajectories=group_skill_map,
            baseline_tokenomics=base_tok_map,
            with_skill_tokenomics=skill_tok_map,
        )

    async def run_and_evaluate_skill_lift(
        self,
        harness: FoundationModelEvalHarness,
        cases: Sequence[SkillEvalCase],
        *,
        skill_name: str,
        skill_md_path: Path | None = None,
        decoy_skills: Sequence[str] = (),
        state_reducer: ShadowStateReducer | None = None,
    ) -> tuple[SkillLiftReport, PairedRolloutBundle]:
        """Execute paired rollouts and score them through :class:`FoundationModelEvalHarness`."""
        bundle = await self.run_paired_rollouts(
            cases,
            skill_name=skill_name,
            skill_md_path=skill_md_path,
            decoy_skills=decoy_skills,
        )
        report = await harness.evaluate_paired_skill_lift(
            skill_name=skill_name,
            model_id=bundle.model_id,
            cases=cases,
            baseline_trajectories=bundle.baseline_trajectories,
            with_skill_trajectories=bundle.with_skill_trajectories,
            group_baseline_trajectories=bundle.group_baseline_trajectories,
            group_with_skill_trajectories=bundle.group_with_skill_trajectories,
            state_reducer=state_reducer,
        )
        return report, bundle


__all__ = [
    "MODEL_PRICING_CATALOG",
    "ADKSessionRolloutAdapter",
    "AgentRolloutRunner",
    "BaseRolloutAdapter",
    "CallableRolloutAdapter",
    "HttpRolloutAdapter",
    "MultiAgentRolloutAdapter",
    "PairedRolloutBundle",
    "RolloutWorkspaceContext",
    "TrajectoryTokenomics",
    "compute_cost_savings_multiplier",
    "compute_trajectory_tokenomics",
    "estimate_token_count",
    "load_rollout_adapter",
]
