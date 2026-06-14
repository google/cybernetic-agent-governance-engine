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

FROM node:18-alpine AS builder

WORKDIR /app

# Copy the lockfile from the monorepo root so it is present in the build
# context.  This ensures the build fails fast if the repo root uv.lock is
# absent (e.g. when the image is built with a narrow context by mistake).
COPY uv.lock ./

# Copy only the UI package manifests first to maximise Docker layer caching.
COPY src/agentsight-ui/package*.json ./

# Install Node dependencies using the public registry.
RUN npm install --legacy-peer-deps

# Copy the rest of the UI source tree.
COPY src/agentsight-ui/ .

RUN npm run build

# Stage 2: Serve via Nginx (unprivileged — runs as UID 101, satisfies PSA restricted)
# nginxinc/nginx-unprivileged is the official drop-in replacement for nginx:alpine
# that binds to port 8080 instead of 80 and runs as a non-root user (nginx, UID 101).
FROM nginxinc/nginx-unprivileged:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
