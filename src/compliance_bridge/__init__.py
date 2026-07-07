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


def __getattr__(name: str):
    """Lazy sub-module resolver for the compliance_bridge package.

    Python calls ``__getattr__`` on a package object when an attribute lookup
    fails (i.e., the sub-module has not yet been imported and cached as a
    package attribute).  This enables ``patch("src.compliance_bridge.main.Langfuse")``
    to work correctly in tests:

    1. ``patch()`` resolves ``"src.compliance_bridge.main"`` by calling
       ``getattr(src.compliance_bridge, "main")``.
    2. This triggers ``__getattr__("main")``, which imports the sub-module.
    3. Because ``mock.patch`` sets up its ``MagicMock`` *before* entering the
       ``with`` block, the Langfuse name inside ``main`` is replaced before
       any test code runs.

    The lazy approach avoids importing ``main`` at package init time, which
    would pull in ``audit_workflow`` → ``from langfuse import Langfuse``,
    failing in environments where langfuse is not installed (pure unit tests).
    """
    import importlib

    try:
        module = importlib.import_module(f"src.compliance_bridge.{name}")
        # Cache on the package so subsequent accesses are fast (no re-import).
        globals()[name] = module
        return module
    except ModuleNotFoundError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
