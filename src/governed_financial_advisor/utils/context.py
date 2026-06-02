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

"""
User Context Module

Provides a ContextVar for passing user identity through the request lifecycle.
This allows tools and agents to access the current user without explicit passing.
"""
from contextvars import ContextVar

# Thread-safe context variable for current user identity
user_context: ContextVar[str] = ContextVar("user_context", default="default_user")
