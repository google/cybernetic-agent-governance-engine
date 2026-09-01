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

"""Plugin-supplied background task registry.

Allows domain plugins to register long-running background coroutines (e.g.
audit workers, polling daemons) that are started during application lifespan.

PR B, T-B6: Moves audit worker startup behind the plugin seam so the kernel
does not directly import from cage_finance.consensus.
"""

import asyncio
import logging
from typing import Awaitable, Callable

logger = logging.getLogger("Gateway.Governance.BackgroundTasks")

_STARTUP_TASKS: list[tuple[str, Callable[[], Awaitable[None]]]] = []


def register_background_task(
    name: str, coro_factory: Callable[[], Awaitable[None]]
) -> None:
    """Register a coroutine factory to be started at application lifespan.
    
    Args:
        name: Human-readable task name (e.g. "consensus_audit")
        coro_factory: A callable that returns an awaitable. The factory will
                      be called once during lifespan startup to create the
                      background task.
    
    Example:
        >>> register_background_task("consensus_audit", _background_audit_worker)
        >>> # Later, during server lifespan:
        >>> tasks = start_all()
    """
    _STARTUP_TASKS.append((name, coro_factory))
    logger.info(f"✅ Registered background task: {name}")


def start_all() -> list[asyncio.Task]:
    """Start all registered background tasks.
    
    Called during application lifespan startup. Each task is named and
    configured with a done callback that logs CRITICAL if the task exits
    unexpectedly (closing Finding B silent-death gap).
    
    Returns:
        List of asyncio.Task objects that can be cancelled during shutdown.
    """
    tasks = []
    for name, factory in _STARTUP_TASKS:
        task = asyncio.create_task(factory(), name=f"cage.bg.{name}")
        task.add_done_callback(_log_task_death)
        tasks.append(task)
        logger.info(f"🚀 Started background task: {name}")
    return tasks


def _log_task_death(task: asyncio.Task) -> None:
    """Log CRITICAL if a background task exits unexpectedly.
    
    This closes the silent-death gap where a background task raising an
    exception would fail silently. Now we log at CRITICAL level so the
    failure is visible in monitoring.
    """
    if task.cancelled():
        # Normal shutdown via cancel() - no log needed
        return
    
    exc = task.exception()
    if exc is not None:
        logger.critical(
            "🚨 Background task %s died with exception: %s",
            task.get_name(),
            exc,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
    else:
        # Task completed normally (shouldn't happen for long-running tasks)
        logger.warning(
            "Background task %s completed unexpectedly (expected to run forever)",
            task.get_name(),
        )
