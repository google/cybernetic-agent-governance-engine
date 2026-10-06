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

"""Regional overlay of domain threshold sections.

``config/governance_thresholds.json`` holds the global ``domains.<section>``
blocks. A deployment region may tighten them: the ``domains`` object of
``config/thresholds/{REGION}_BASELINE.json`` is deep-merged onto the global
blocks when the thresholds are loaded, so every ``THRESHOLDS.resolve(...)``
reader (CBF ``threshold_key``, STPA ``threshold_ref``, domain tiers) sees the
region's effective values.

The kernel treats each section as an opaque tree. It never names a domain
key; the domain plugin's own schema validates the merged section at governor
assembly (``assembly._validate_threshold_sections``), and an unknown or
invalid key fails assembly there. The merge itself fails closed when:

* the regional file is missing, unreadable, or its ``domains`` is not an
  object of objects;
* a regional section has no global counterpart (a region tunes a domain the
  global file declares; it cannot add one);
* a regional value would replace an object with a scalar or vice versa.

Keys starting with ``_`` are annotations (``_comment``, citations). They are
dropped from the effective sections, so domain schemas can forbid unknown
keys without tripping over documentation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

#: Directory holding the per-region ``{REGION}_BASELINE.json`` files.
REGIONAL_THRESHOLDS_DIR: Path = (
    Path(__file__).resolve().parents[4] / "config" / "thresholds"
)

_ANNOTATION_PREFIX = "_"


class RegionalOverlayError(ValueError):
    """The regional baseline cannot be overlaid onto the global thresholds."""


def regional_baseline_path(
    region: str, directory: Path = REGIONAL_THRESHOLDS_DIR
) -> Path:
    """Path of ``region``'s threshold baseline (``{REGION}_BASELINE.json``)."""
    return directory / f"{region}_BASELINE.json"


def load_regional_domains(
    region: str, directory: Path = REGIONAL_THRESHOLDS_DIR
) -> dict[str, dict[str, Any]]:
    """The ``domains`` object of ``region``'s baseline (``{}`` if it declares none).

    Raises:
        RegionalOverlayError: The file is missing or malformed, or ``domains``
            is not an object whose values are objects.
    """
    path = regional_baseline_path(region, directory)
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise RegionalOverlayError(
            f"cannot read regional threshold baseline {path}: {exc}"
        ) from exc
    if not isinstance(raw, Mapping):
        raise RegionalOverlayError(f"{path} must contain a JSON object")
    domains = raw.get("domains", {})
    if not isinstance(domains, Mapping):
        raise RegionalOverlayError(f"{path}: 'domains' must be an object")
    sections: dict[str, dict[str, Any]] = {}
    for name, section in domains.items():
        if _is_annotation(name):
            continue
        if not isinstance(section, Mapping):
            raise RegionalOverlayError(
                f"{path}: 'domains.{name}' must be an object, "
                f"got {type(section).__name__}"
            )
        sections[name] = dict(section)
    return sections


def overlay_domains(
    base: Mapping[str, Mapping[str, Any]],
    overlay: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Deep-merge regional ``overlay`` sections onto the global ``base`` sections.

    Returns a new tree (inputs are not mutated) with annotation keys removed.
    Lists and scalars in ``overlay`` replace the global value; objects merge
    key by key.

    Raises:
        RegionalOverlayError: A regional section has no global counterpart, or
            a value changes shape (object vs. non-object).
    """
    merged: dict[str, dict[str, Any]] = {
        name: _strip_annotations(section)
        for name, section in base.items()
        if not _is_annotation(name)
    }
    for name, section in overlay.items():
        if _is_annotation(name):
            continue
        if name not in merged:
            raise RegionalOverlayError(
                f"regional section 'domains.{name}' has no global counterpart "
                "in governance_thresholds.json"
            )
        merged[name] = _merge(merged[name], section, f"domains.{name}")
    return merged


def _is_annotation(key: object) -> bool:
    return isinstance(key, str) and key.startswith(_ANNOTATION_PREFIX)


def _strip_annotations(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            k: _strip_annotations(v) for k, v in value.items() if not _is_annotation(k)
        }
    return value


def _merge(
    base: Mapping[str, Any], overlay: Mapping[str, Any], path: str
) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if _is_annotation(key):
            continue
        here = f"{path}.{key}"
        if key in merged:
            base_is_object = isinstance(merged[key], Mapping)
            if base_is_object != isinstance(value, Mapping):
                raise RegionalOverlayError(
                    f"regional value for '{here}' changes shape: global is "
                    f"{type(merged[key]).__name__}, regional is {type(value).__name__}"
                )
            if base_is_object:
                merged[key] = _merge(merged[key], value, here)
                continue
        merged[key] = _strip_annotations(value)
    return merged


__all__ = [
    "REGIONAL_THRESHOLDS_DIR",
    "RegionalOverlayError",
    "load_regional_domains",
    "overlay_domains",
    "regional_baseline_path",
]
