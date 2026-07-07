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

"""Replay failed Langfuse score postings from ``failed_scores.jsonl``.

Usage (from repo root)::

    uv run python scripts/replay_failed_scores.py

Each line in ``failed_scores.jsonl`` is a JSON object written by
``_post_score_with_retry()`` in ``scripts/evaluate_langfuse_traces.py`` when
all retry attempts are exhausted.  This script reads the file, attempts to
re-post every entry using the same ``_post_score_with_retry()`` helper (which
includes its own exponential-backoff retry loop), and writes successfully
replayed entries to ``failed_scores_replayed.jsonl``.  Successfully replayed
entries are removed from ``failed_scores.jsonl``; still-failing entries remain
so the script is safe to re-run.

Environment variables required:
    LANGFUSE_PUBLIC_KEY   Langfuse project public key
    LANGFUSE_SECRET_KEY   Langfuse project secret key
    LANGFUSE_HOST         Langfuse host URL (default: http://localhost:3000)
"""

import datetime
import json
import logging
import os
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

from langfuse import Langfuse

# ---------------------------------------------------------------------------
# Retry constants — mirrors evaluate_langfuse_traces.py
# ---------------------------------------------------------------------------
_RETRY_DELAYS = (1, 2, 4)  # seconds — exponential backoff, 3 attempts

FAILED_SCORES_PATH = "failed_scores.jsonl"
REPLAYED_SCORES_PATH = "failed_scores_replayed.jsonl"


# ---------------------------------------------------------------------------
# Resilient score-posting helper (same contract as in evaluate_langfuse_traces)
# ---------------------------------------------------------------------------


def _post_score_with_retry(
    langfuse_client,
    *,
    trace_id: str,
    name: str,
    value: float,
    comment: str = "",
) -> bool:
    """Post a single score to Langfuse with up to 3 retries and exponential backoff.

    Returns True when the score was successfully posted, False after all retries
    are exhausted.  Never raises — a WARNING is logged on every failure.
    """
    import httpx
    import requests as _requests

    kwargs = dict(trace_id=trace_id, name=name, value=value, comment=comment)
    last_exc: Exception | None = None

    for attempt, delay in enumerate(_RETRY_DELAYS, start=1):
        try:
            langfuse_client.create_score(**kwargs)
            if attempt > 1:
                logger.info(
                    "[langfuse] score '%s' posted successfully on attempt %d.",
                    name,
                    attempt,
                )
            return True
        except (
            httpx.HTTPStatusError,
            _requests.HTTPError,
        ) as exc:
            status = getattr(exc.response, "status_code", "?")
            logger.warning(
                "[langfuse] HTTP %s posting score '%s' (attempt %d/%d). "
                "Retrying in %ds…",
                status,
                name,
                attempt,
                len(_RETRY_DELAYS),
                delay,
            )
            last_exc = exc
        except Exception as exc:
            logger.warning(
                "[langfuse] Unexpected error posting score '%s' (attempt %d/%d): %s. "
                "Retrying in %ds…",
                name,
                attempt,
                len(_RETRY_DELAYS),
                exc,
                delay,
            )
            last_exc = exc

        time.sleep(delay)

    logger.warning(
        "[langfuse] FAILED to post score '%s' for trace %s after %d attempts. "
        "Last error: %s.",
        name,
        trace_id,
        len(_RETRY_DELAYS),
        last_exc,
    )
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def replay_failed_scores() -> None:
    """Read ``failed_scores.jsonl``, attempt to replay each entry, report summary."""

    # ── Langfuse client ───────────────────────────────────────────────────────
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST", "http://localhost:3000")

    if not public_key or not secret_key:
        print(
            "ERROR: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set.",
            file=sys.stderr,
        )
        sys.exit(1)

    langfuse_client = Langfuse(public_key=public_key, secret_key=secret_key, host=host)

    # ── Read pending entries ──────────────────────────────────────────────────
    if not os.path.exists(FAILED_SCORES_PATH):
        print(f"No {FAILED_SCORES_PATH} found — nothing to replay.")
        return

    with open(FAILED_SCORES_PATH, encoding="utf-8") as fh:
        raw_lines = fh.readlines()

    if not raw_lines:
        print(f"{FAILED_SCORES_PATH} is empty — nothing to replay.")
        return

    print(f"Found {len(raw_lines)} failed score(s) to replay…")

    replayed_count = 0
    failed_count = 0
    still_failing_lines: list[str] = []

    for line_no, raw_line in enumerate(raw_lines, start=1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue  # skip blank lines

        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            logger.warning(
                "Line %d: invalid JSON — keeping as-is. Error: %s", line_no, exc
            )
            still_failing_lines.append(raw_line)
            failed_count += 1
            continue

        trace_id = entry.get("trace_id", "")
        name = entry.get("name", "")
        value = entry.get("value")
        comment = entry.get("comment", "")

        if value is None:
            logger.warning("Line %d: missing 'value' field — skipping entry.", line_no)
            still_failing_lines.append(raw_line)
            failed_count += 1
            continue

        success = _post_score_with_retry(
            langfuse_client,
            trace_id=trace_id,
            name=name,
            value=float(value),
            comment=comment,
        )

        if success:
            replayed_count += 1
            # Record the replayed entry for audit purposes
            replay_record = {
                **entry,
                "replayed_at": datetime.datetime.utcnow().isoformat() + "Z",
            }
            try:
                with open(REPLAYED_SCORES_PATH, "a", encoding="utf-8") as rfh:
                    rfh.write(json.dumps(replay_record) + "\n")
            except Exception as write_exc:
                logger.warning(
                    "Could not append to %s: %s", REPLAYED_SCORES_PATH, write_exc
                )
        else:
            still_failing_lines.append(raw_line)
            failed_count += 1

    # ── Rewrite failed_scores.jsonl with only the still-failing entries ───────
    try:
        with open(FAILED_SCORES_PATH, "w", encoding="utf-8") as fh:
            for line in still_failing_lines:
                fh.write(line + "\n")
        if not still_failing_lines:
            # File is now empty — optionally remove it
            os.remove(FAILED_SCORES_PATH)
            print(f"  ✅ {FAILED_SCORES_PATH} removed (all entries replayed).")
        else:
            print(
                f"  ⚠️  {len(still_failing_lines)} entry/entries still failing "
                f"— kept in {FAILED_SCORES_PATH} for a future retry."
            )
    except Exception as exc:
        logger.warning("Could not rewrite %s: %s", FAILED_SCORES_PATH, exc)

    # ── Flush queued score events before exit ─────────────────────────────────
    try:
        langfuse_client.flush()
        logger.info("[langfuse] flush() completed successfully.")
    except Exception as flush_exc:
        logger.warning(
            "[langfuse] flush() raised an exception (scores may be incomplete): %s",
            flush_exc,
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\nReplayed {replayed_count} scores, failed {failed_count}.")
    if replayed_count:
        print(f"  Replayed entries appended to {REPLAYED_SCORES_PATH}.")


if __name__ == "__main__":
    replay_failed_scores()
