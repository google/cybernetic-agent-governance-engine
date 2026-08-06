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

"""gen_tfvars.py — .env → terraform.auto.tfvars bridge.

Reads a .env file and emits a terraform.auto.tfvars file containing the three
sensitive Terraform variables that must be populated before ``terraform apply``:

    routing_seal_secret          ← CAGE_ROUTING_SEAL_SECRET
    kms_governance_key           ← KMS_GOVERNANCE_KEY
    otel_exporter_otlp_headers   ← OTEL_EXPORTER_OTLP_HEADERS
                                    (derived from LANGFUSE_PUBLIC_KEY +
                                     LANGFUSE_SECRET_KEY if not set directly)

Secret hygiene (AGENTS.md — non-negotiable):
  • No secret value is ever embedded as a Python string literal in this file.
  • Log output masks every secret: value[:4] + "****".
  • ``--dry-run`` prints masked values only; never writes to disk.
  • The script never imports os.environ wholesale.
  • The output file (terraform.auto.tfvars) is gitignored — verify before use.
"""

from __future__ import annotations

import argparse
import base64
import logging
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s  %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# .env parser — no os.environ import, no python-dotenv dependency
# ---------------------------------------------------------------------------

_ENV_LINE_RE = re.compile(
    r"""
    ^
    \s*
    (?P<key>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s*=\s*
    (?P<value>                          # value (optional)
        "(?:[^"\\]|\\.)*"              #   double-quoted
        |
        '(?:[^'\\]|\\.)*'              #   single-quoted
        |
        [^#\r\n]*                      #   unquoted (no inline comment)
    )
    \s*
    (?:\#.*)?                          # optional trailing comment
    $
    """,
    re.VERBOSE,
)


def _strip_quotes(raw: str) -> str:
    """Remove surrounding single or double quotes from a value string."""
    raw = raw.strip()
    if len(raw) >= 2:
        if (raw[0] == '"' and raw[-1] == '"') or (raw[0] == "'" and raw[-1] == "'"):
            # Unescape common escape sequences inside quoted strings.
            inner = raw[1:-1]
            inner = inner.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
            return inner
    return raw


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file and return a dict of variable names → values.

    Only non-comment, non-blank lines containing an ``=`` sign are parsed.
    Values are stripped of surrounding quotes. Inline comments after unquoted
    values are stripped.  The parser does NOT evaluate shell arithmetic or
    variable references.

    Args:
        path: Path to the .env file to read.

    Returns:
        Mapping of variable name to raw (unquoted) string value.

    Raises:
        SystemExit: If the file cannot be opened or read.
    """
    env: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("Cannot read %s: %s", path, exc)
        sys.exit(1)

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        # Skip blank lines and comment-only lines.
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if m is None:
            # Line has an = but didn't match (e.g. export statements).
            # Try a simpler split as a fallback — still skip comment lines.
            if "=" in stripped and not stripped.startswith("#"):
                key_part, _, val_part = stripped.partition("=")
                key_part = key_part.strip().removeprefix("export").strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_part):
                    env[key_part] = _strip_quotes(val_part.split("#")[0])
            continue
        key = m.group("key")
        raw_value = m.group("value").strip()
        # Strip inline comments from unquoted values.
        if raw_value and raw_value[0] not in ('"', "'"):
            raw_value = raw_value.split("#")[0].rstrip()
        env[key] = _strip_quotes(raw_value)
        log.debug("Line %d: parsed %s", lineno, key)

    return env


# ---------------------------------------------------------------------------
# Secret masking — AGENTS.md obligation
# ---------------------------------------------------------------------------


def _mask(value: str) -> str:
    """Return a masked representation of *value* safe to log.

    Shows the first four characters followed by ``****``.  If the value is
    shorter than five characters the entire value is replaced with ``****``.
    """
    if not value:
        return "(empty)"
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


# ---------------------------------------------------------------------------
# OTLP header derivation
# ---------------------------------------------------------------------------


def _derive_otlp_headers(pub: str, secret: str) -> str:
    """Derive the OTLP Authorization header from Langfuse public + secret keys.

    The derived format matches Langfuse's HTTP Basic Auth expectation:
    ``Authorization=Basic <base64(public_key:secret_key)>``

    Args:
        pub:    Langfuse public key (e.g. ``pk-lf-...``).
        secret: Langfuse secret key (e.g. ``sk-lf-...``).

    Returns:
        Complete header string ready for use as ``otel_exporter_otlp_headers``.
    """
    credential = f"{pub}:{secret}"
    encoded = base64.b64encode(credential.encode()).decode()
    return f"Authorization=Basic {encoded}"


# ---------------------------------------------------------------------------
# tfvars writer
# ---------------------------------------------------------------------------

_TFVARS_HEADER = """\
# terraform.auto.tfvars — AUTO-GENERATED by scripts/gen_tfvars.py
# DO NOT EDIT MANUALLY.  Re-run the script to regenerate.
# This file is gitignored (see .gitignore line: terraform.auto.tfvars).
# It must NEVER be committed to version control.
#
# Source: {source}
"""


def build_tfvars_content(
    routing_seal_secret: str,
    kms_governance_key: str,
    otel_exporter_otlp_headers: str,
    source_path: Path,
) -> str:
    """Return the full content of the terraform.auto.tfvars file as a string.

    Args:
        routing_seal_secret:        Value for ``routing_seal_secret``.
        kms_governance_key:         Value for ``kms_governance_key``.
        otel_exporter_otlp_headers: Value for ``otel_exporter_otlp_headers``.
        source_path:                Path of the originating .env file.

    Returns:
        Formatted HCL string ready to write to ``terraform.auto.tfvars``.
    """

    def _hcl_str(v: str) -> str:
        # Escape backslashes and double-quotes for HCL string literals.
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = [
        _TFVARS_HEADER.format(source=source_path.resolve()),
        f"routing_seal_secret        = {_hcl_str(routing_seal_secret)}",
        f"kms_governance_key         = {_hcl_str(kms_governance_key)}",
        f"otel_exporter_otlp_headers = {_hcl_str(otel_exporter_otlp_headers)}",
        "",  # trailing newline
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate terraform.auto.tfvars from a .env file.\n\n"
            "Reads CAGE_ROUTING_SEAL_SECRET, KMS_GOVERNANCE_KEY, and\n"
            "OTEL_EXPORTER_OTLP_HEADERS from the given .env file and writes\n"
            "a gitignored terraform.auto.tfvars file suitable for use with\n"
            "'terraform apply'.\n\n"
            "If OTEL_EXPORTER_OTLP_HEADERS is absent, derives it from\n"
            "LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY using HTTP Basic Auth."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env",
        default=".env",
        metavar="PATH",
        help="Path to the source .env file (default: .env)",
    )
    parser.add_argument(
        "--output",
        default="infra/targets/gcp-gke/terraform.auto.tfvars",
        metavar="PATH",
        help=(
            "Destination path for the generated terraform.auto.tfvars file "
            "(default: infra/targets/gcp-gke/terraform.auto.tfvars)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Print masked variable values to stderr and exit without writing any file."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:  # noqa: C901
    """Entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code — 0 on success, 1 on error.
    """
    args = parse_args(argv)

    env_path = Path(args.env)
    output_path = Path(args.output)

    log.info("Reading env vars from: %s", env_path)
    env = parse_env_file(env_path)

    # ── 1. routing_seal_secret ────────────────────────────────────────────
    routing_seal_secret = env.get("CAGE_ROUTING_SEAL_SECRET", "").strip()
    if not routing_seal_secret:
        log.error(
            "CAGE_ROUTING_SEAL_SECRET is missing or empty in %s.\n"
            "  Generate a value with:\n"
            '    python -c "import secrets; print(secrets.token_hex(32))"',
            env_path,
        )
        return 1

    # ── 2. kms_governance_key ────────────────────────────────────────────
    kms_governance_key = env.get("KMS_GOVERNANCE_KEY", "").strip()
    if not kms_governance_key:
        log.error(
            "KMS_GOVERNANCE_KEY is missing or empty in %s.\n"
            "  Expected format:\n"
            "    projects/PROJECT/locations/LOCATION/keyRings/RING"
            "/cryptoKeys/KEY/cryptoKeyVersions/VERSION",
            env_path,
        )
        return 1

    # ── 3. otel_exporter_otlp_headers (direct or derived) ────────────────
    otlp_headers = env.get("OTEL_EXPORTER_OTLP_HEADERS", "").strip()
    otlp_source = "OTEL_EXPORTER_OTLP_HEADERS"

    if not otlp_headers:
        pub = env.get("LANGFUSE_PUBLIC_KEY", "").strip()
        sec = env.get("LANGFUSE_SECRET_KEY", "").strip()

        if not pub or not sec:
            log.error(
                "OTEL_EXPORTER_OTLP_HEADERS is not set in %s and cannot be\n"
                "  derived because LANGFUSE_PUBLIC_KEY and/or LANGFUSE_SECRET_KEY\n"
                "  are also missing or empty.\n\n"
                "  Either:\n"
                "    (a) Set OTEL_EXPORTER_OTLP_HEADERS directly, or\n"
                "    (b) Set both LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY\n"
                "        so the script can derive the Basic Auth header.",
                env_path,
            )
            return 1

        otlp_headers = _derive_otlp_headers(pub, sec)
        otlp_source = "derived from LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY"
        log.info("OTEL_EXPORTER_OTLP_HEADERS: derived via Basic Auth (%s)", otlp_source)

    # ── Masked preview (always emitted for operator confirmation) ─────────
    log.info("Variable resolution summary (values masked):")
    log.info("  routing_seal_secret        = %s", _mask(routing_seal_secret))
    log.info("  kms_governance_key         = %s", _mask(kms_governance_key))
    log.info(
        "  otel_exporter_otlp_headers = %s  [source: %s]",
        _mask(otlp_headers),
        otlp_source,
    )

    if args.dry_run:
        log.info("--dry-run: skipping file write. No disk changes made.")
        return 0

    # ── Write output file ─────────────────────────────────────────────────
    content = build_tfvars_content(
        routing_seal_secret=routing_seal_secret,
        kms_governance_key=kms_governance_key,
        otel_exporter_otlp_headers=otlp_headers,
        source_path=env_path,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    log.info("Written: %s", output_path.resolve())

    return 0


if __name__ == "__main__":
    sys.exit(main())
